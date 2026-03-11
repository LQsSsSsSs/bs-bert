import torch
import sys
import os
import pickle
import numpy as np
from transformers import BertTokenizerFast, BertForSequenceClassification
from peft import PeftModel
from sklearn.preprocessing import LabelEncoder
from cvss import CVSS3

# 配置
MODEL_DIR = "bert-classifier"
BASE_MODEL = "prajjwal1/bert-small"

# 我们的指标名称到 CVSS 向量缩写的映射
METRIC_MAPPING = {
    "cvssV3_attackVector": "AV",
    "cvssV3_attackComplexity": "AC",
    "cvssV3_privilegesRequired": "PR",
    "cvssV3_userInteraction": "UI",
    "cvssV3_scope": "S",
    "cvssV3_confidentialityImpact": "C",
    "cvssV3_integrityImpact": "I",
    "cvssV3_availabilityImpact": "A"
}

# 值缩写的映射（模型预测完整的单词如 'NETWORK'，CVSS 需要 'N'）
# 这取决于数据的训练方式。我们假设使用标准映射或检查 label.txt
# 标准 CVSS v3.1 值：
VALUE_MAPPING = {
    # 攻击向量 (Attack Vector)
    "NETWORK": "N", "ADJACENT_NETWORK": "A", "LOCAL": "L", "PHYSICAL": "P",
    # 攻击复杂度 (Attack Complexity)
    "LOW": "L", "HIGH": "H",
    # 权限要求 (Privileges Required)
    "NONE": "N", "LOW": "L", "HIGH": "H",
    # 用户交互 (User Interaction)
    "NONE": "N", "REQUIRED": "R",
    # 范围 (Scope)
    "UNCHANGED": "U", "CHANGED": "C",
    # CIA 影响 (CIA Impact)
    "NONE": "N", "LOW": "L", "HIGH": "H"
}

class CVSSPredictor:
    def __init__(self):
        self.device = torch.device('cuda') if torch.cuda.is_available() else torch.device('cpu')
        self.tokenizer = BertTokenizerFast.from_pretrained(BASE_MODEL)
        self.models = {}
        self.encoders = {}
        
        print(f"正在 {self.device} 上加载模型...")
        self._load_all_models()
        
    def _load_all_models(self):
        for metric in METRIC_MAPPING.keys():
            metric_path = os.path.join(MODEL_DIR, metric)
            model_path = os.path.join(metric_path, "model")
            label_path = os.path.join(metric_path, "label.txt")
            
            if not os.path.exists(model_path) or not os.path.exists(label_path):
                print(f"警告: 未找到 {metric} 的模型。跳过。")
                continue
                
            # 1. 加载标签编码器
            with open(label_path, "rb") as f:
                classes = pickle.load(f)
                le = LabelEncoder()
                le.classes_ = classes
                self.encoders[metric] = le
                
            # 2. 加载模型 (基础模型 + LoRA)
            num_labels = len(classes)
            # 加载基础模型
            base_model = BertForSequenceClassification.from_pretrained(BASE_MODEL, num_labels=num_labels)
            # 加载 LoRA 适配器
            model = PeftModel.from_pretrained(base_model, model_path)
            model.to(self.device)
            model.eval()
            self.models[metric] = model
            
    def predict(self, text):
        inputs = self.tokenizer(text, truncation=True, padding=True, max_length=128, return_tensors="pt")
        inputs = {k: v.to(self.device) for k, v in inputs.items()}
        
        results = {}
        vector_components = []
        
        print("\n预测结果:")
        print("-" * 50)
        
        for metric, short_name in METRIC_MAPPING.items():
            if metric not in self.models:
                continue
                
            model = self.models[metric]
            le = self.encoders[metric]
            
            with torch.no_grad():
                outputs = model(**inputs)
                logits = outputs.logits
                pred_id = torch.argmax(logits, dim=1).item()
                confidence = torch.softmax(logits, dim=1).max().item()
                
            pred_label = le.inverse_transform([pred_id])[0]
            results[metric] = pred_label
            
            # 映射到 CVSS 向量格式
            short_value = VALUE_MAPPING.get(pred_label, pred_label[0]) # 如果未找到则回退到首字母
            vector_components.append(f"{short_name}:{short_value}")
            
            print(f"{metric:<30} : {pred_label:<15} (置信度: {confidence:.2f})")
            
        # 构建向量字符串
        vector_string = "CVSS:3.1/" + "/".join(vector_components)
        print("-" * 50)
        print(f"生成的向量: {vector_string}")
        
        # 计算评分
        try:
            c = CVSS3(vector_string)
            print(f"基础评分 (Base Score) : {c.base_score}")
            print(f"严重程度 (Severity)   : {c.severities()[0]}")
        except Exception as e:
            print(f"评分计算错误: {e}")
            
        return vector_string

if __name__ == "__main__":
    predictor = CVSSPredictor()
    
    print("\n" + "="*60)
    print("CVSS-BERT 预测器已就绪")
    print("请输入漏洞描述以预测其 CVSS 向量。")
    print("输入 'exit' 或 'quit' 停止。")
    print("="*60 + "\n")
    
    while True:
        try:
            text = input(">> 漏洞描述: ")
            if text.lower() in ['exit', 'quit']:
                break
            if not text.strip():
                continue
                
            predictor.predict(text)
            print("\n")
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"错误: {e}")
