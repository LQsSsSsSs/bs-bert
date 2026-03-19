#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
CVSS-BERT 统一训练脚本。
合并了 train.py（单指标训练）和 train_all_metrics.py（批量训练）的功能。
"""

import sys
import os
import argparse
import subprocess
import ast
import pandas as pd
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm

# 导入项目特定模块
# 确保如果从根目录运行，脚本可以找到包
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from explainable_bert_classifier.data import fit_transform_LabelEncoder, tokenizer, CVEDataset, split_dataset
    from explainable_bert_classifier.model import BertClassifier
except ImportError as e:
    # 仅当我们运行在可能不需要这些模块的模式下（例如 help）时才打印警告，
    # 但严格来说，我们通常需要它们。
    # 我们允许它在这里通过，但如果稍后使用它将会失败。
    print(f"警告: 无法导入 explainable_bert_classifier 模块。{e}")

# ==========================================
# 配置 / 常量
# ==========================================
DEFAULT_INPUT_DATA = 'data/cve_2023-2025'
DEFAULT_OUTPUT_DIR = 'bert-classifier'
DEFAULT_METRIC_NAME = 'cvssV3_confidentialityImpact'

# 批量训练的指标列表
METRICS = [
    "cvssV3_attackVector",
    "cvssV3_attackComplexity",
    "cvssV3_privilegesRequired",
    "cvssV3_userInteraction",
    "cvssV3_scope",
    "cvssV3_confidentialityImpact",
    "cvssV3_integrityImpact",
    "cvssV3_availabilityImpact",
    "CWE1"
]

MAX_WORKERS = 2  # 并行工作线程
EPOCHS = 10      # 必须与训练器配置匹配

# ==========================================
# 单指标训练逻辑
# ==========================================
def train_single_metric(input_data, output_dir, metric_name):
    """
    执行单个指标的训练过程。
    """
    print(f"开始训练指标: {metric_name}")
    print(f"输入数据: {input_data}")
    print(f"输出目录: {output_dir}")

    # 创建目录
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    metric_output_dir = os.path.join(output_dir, metric_name)
    if not os.path.exists(metric_output_dir):
        os.makedirs(metric_output_dir)
    
    # 加载数据
    try:
        X_train = pd.read_csv(input_data+'_X_train.csv')
        y_train = pd.read_csv(input_data+'_y_train.csv')
    except FileNotFoundError:
        print(f"错误: 在 {input_data}_X_train.csv 或 {input_data}_y_train.csv 未找到数据文件")
        sys.exit(1)
    
    if metric_name not in y_train.columns:
        print(f"错误: 训练数据中未找到指标 '{metric_name}'。")
        sys.exit(1)

    # 编码标签
    train_labels = y_train.loc[:, metric_name]
    encoded_train_labels = fit_transform_LabelEncoder(
        train_labels, 
        save=True, 
        filename=os.path.join(metric_output_dir, 'label.txt')
    )

    mytokenizer = tokenizer()
    
    # 分割数据集
    print('正在分割验证数据集...')
    train_dataset, val_dataset = split_dataset(X_train, train_labels, encoded_train_labels, mytokenizer, val_proportion=0.1)

    # 初始化模型
    print('正在加载带有 LoRA 的模型...')
    NUM_CLASSES = len(set(train_labels))
    classifier = BertClassifier(num_labels=NUM_CLASSES)

    # 训练
    print('正在训练...')
    # output_dir 传递给 Trainer，由它记录日志。
    classifier.fit(train_dataset, val_dataset, output_dir=metric_output_dir, epochs=EPOCHS, batch_size=16)
    
    # 保存模型
    print('正在保存模型...')
    classifier.model.save_pretrained(os.path.join(metric_output_dir, 'model'))
    print('训练完成。')


# ==========================================
# 批量训练逻辑
# ==========================================
def _run_subprocess_train(args):
    """
    在子进程中运行训练的工作函数。
    args: (metric, position, input_data, output_dir)
    """
    metric, position, input_data, output_dir = args
    
    metric_dir = os.path.join(output_dir, metric)
    os.makedirs(metric_dir, exist_ok=True)
    
    python_executable = sys.executable
    # 使用自身的绝对路径，确保我们调用的是同一个脚本
    script_path = os.path.abspath(__file__)
    
    # 调用此脚本并带上 -m 参数来运行单指标训练
    cmd = [python_executable, "-u", script_path, "-i", input_data, "-o", output_dir, "-m", metric]
    
    # 初始化 tqdm 进度条
    # position 控制进度条的行偏移
    pbar = tqdm(total=EPOCHS, desc=f"{metric:<30}", position=position, leave=True, unit="epoch", 
                bar_format="{desc} |{bar:20}| {n_fmt}/{total_fmt} [{postfix}]")
    
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding='utf-8',
            errors='replace',
            bufsize=1
        )
        
        current_epoch = 0.0
        
        # 监控子进程输出
        for line in iter(process.stdout.readline, ''):
            line = line.strip()
            if not line:
                continue
            
            # 检查来自 Hugging Face Trainer 的类似 JSON 的日志
            # 模式: {'loss': 0.123, ... 'epoch': 1.0}
            if line.startswith("{") and "'loss':" in line:
                try:
                    safe_line = line.replace("nan", "0")
                    log_data = ast.literal_eval(safe_line)
                    
                    if 'epoch' in log_data:
                        new_epoch = float(log_data['epoch'])
                        increment = new_epoch - current_epoch
                        if increment > 0:
                            pbar.update(increment)
                            current_epoch = new_epoch
                            
                    if 'loss' in log_data:
                        pbar.set_postfix(loss=f"{log_data['loss']:.4f}")
                        
                except Exception:
                    pass
            
            # 模式: {'eval_loss': ..., 'eval_accuracy': ...}
            elif line.startswith("{") and "'eval_accuracy':" in line:
                try:
                    safe_line = line.replace("nan", "0")
                    log_data = ast.literal_eval(safe_line)
                    if 'eval_accuracy' in log_data:
                         pbar.set_postfix(acc=f"{log_data['eval_accuracy']:.4f}", loss=pbar.postfix.get('loss', 'N/A'))
                except Exception:
                    pass
                    
        return_code = process.wait()
        pbar.close()
        
        if return_code == 0:
            tqdm.write(f"✅ {metric} 已完成")
            return True
        else:
            tqdm.write(f"❌ {metric} 失败 (退出代码: {return_code})")
            return False
            
    except Exception as e:
        pbar.close()
        tqdm.write(f"❌ {metric} 错误: {e}")
        return False

def train_all_metrics(input_data, output_dir):
    # 清除屏幕以便更好地查看进度条
    os.system('cls' if os.name == 'nt' else 'clear')
    
    print(f"开始批量训练 {len(METRICS)} 个指标...")
    print(f"并行工作线程: {MAX_WORKERS} | 输入数据: {input_data}")
    print("-" * 60)
    
    all_results = []
    
    # 分块处理以管理进度条位置
    for i in range(0, len(METRICS), MAX_WORKERS):
        chunk = METRICS[i : i + MAX_WORKERS]
        
        # 准备参数: (metric, position, input_data, output_dir)
        # idx 决定进度条的垂直位置
        task_args = [(metric, idx, input_data, output_dir) for idx, metric in enumerate(chunk)]
        
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            results = list(executor.map(_run_subprocess_train, task_args))
            all_results.extend(results)
    
    print("-" * 60)
    print(f"成功训练: {sum(all_results)}/{len(METRICS)}")


# ==========================================
# 主入口点
# ==========================================
def main():
    parser = argparse.ArgumentParser(description="CVSS-BERT 训练脚本")
    
    # 模式选择
    parser.add_argument('--all', action='store_true', help="按顺序/并行训练所有指标")
    
    # 通用参数
    parser.add_argument('-i', '--input_data', type=str, default=DEFAULT_INPUT_DATA, help="输入数据路径（不带扩展名）")
    parser.add_argument('-o', '--output_dir', type=str, default=DEFAULT_OUTPUT_DIR, help="保存模型的目录")
    parser.add_argument('-m', '--metric_name', type=str, default=DEFAULT_METRIC_NAME, help="要训练的具体指标（如果设置了 --all 则忽略）")
    
    args = parser.parse_args()
    
    if args.all:
        train_all_metrics(args.input_data, args.output_dir)
    else:
        train_single_metric(args.input_data, args.output_dir, args.metric_name)

if __name__ == "__main__":
    main()
