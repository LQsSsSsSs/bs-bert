import requests
import json
import time
import pandas as pd
import os
from datetime import datetime
from sklearn.model_selection import train_test_split

import sys

# 配置
API_KEY = None  # 在此处添加您的 NVD API 密钥以加快下载速度
BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
YEARS = [2023, 2024, 2025]
OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_PER_PAGE = 2000

def get_cves_for_period(start_date, end_date, sample_mode=False):
    """
    使用 NVD API 2.0 获取特定时间段的 CVE
    """
    cves = []
    start_index = 0
    
    params = {
        'pubStartDate': f"{start_date}T00:00:00.000",
        'pubEndDate': f"{end_date}T23:59:59.999",
        'resultsPerPage': RESULTS_PER_PAGE,
        'startIndex': start_index
    }
    
    headers = {}
    if API_KEY:
        headers['apiKey'] = API_KEY
        
    print(f"正在下载 {start_date} 到 {end_date} 的数据...")
    
    while True:
        params['startIndex'] = start_index
        
        try:
            response = requests.get(BASE_URL, params=params, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])
                cves.extend(vulnerabilities)
                
                total_results = data.get('totalResults', 0)
                print(f"  - 已获取 {len(vulnerabilities)} 条记录 (目前总计: {len(cves)} / {total_results})")
                
                if sample_mode:
                    print("采样模式: 在第一页后停止。")
                    break

                if start_index + len(vulnerabilities) >= total_results:
                    break
                    
                start_index += len(vulnerabilities)
                
                # 速率限制
                if API_KEY:
                    time.sleep(0.6)
                else:
                    time.sleep(6)
            
            elif response.status_code == 403:
                print("  ! 速率受限或被禁止。等待 30 秒...")
                time.sleep(30)
            else:
                print(f"  ! 错误 {response.status_code}: {response.text}")
                print("  ! 10 秒后重试...")
                time.sleep(10)
                
        except Exception as e:
            print(f"  ! 异常: {e}")
            time.sleep(10)
            
    return cves

def download_cves(years, sample_mode=False):
    all_cves = []
    
    # 如果是采样模式，只取最后一年最后的一个季度
    target_years = years if not sample_mode else [years[-1]]
    
    for year in target_years:
        print(f"\n=== 正在处理 {year} 年 ===")
        # 将年份分为季度以满足 120 天的限制
        quarters = [
            (f"{year}-01-01", f"{year}-03-31"),
            (f"{year}-04-01", f"{year}-06-30"),
            (f"{year}-07-01", f"{year}-09-30"),
            (f"{year}-10-01", f"{year}-12-31"),
        ]
        
        # 如果是采样模式，只处理最后一个有效季度
        if sample_mode:
             quarters = [quarters[-1]]

        for start, end in quarters:
            # 跳过未来日期
            if start > datetime.now().strftime("%Y-%m-%d"):
                continue
                
            cves = get_cves_for_period(start, end, sample_mode)
            all_cves.extend(cves)
            
    return all_cves

def parse_cve_data(cve_list):
    parsed_data = []
    
    for item in cve_list:
        try:
            cve_item = item.get('cve', {})
            metrics = cve_item.get('metrics', {})
            
            # 我们优先使用 CVSS v3.1，然后是 v3.0
            cvss_data = None
            if 'cvssMetricV31' in metrics:
                cvss_data = metrics['cvssMetricV31'][0]['cvssData']
            elif 'cvssMetricV30' in metrics:
                cvss_data = metrics['cvssMetricV30'][0]['cvssData']
            
            if not cvss_data:
                continue
                
            cve_id = cve_item.get('id')
            
            # 获取英文描述
            description = ""
            for desc in cve_item.get('descriptions', []):
                if desc.get('lang') == 'en':
                    description = desc.get('value')
                    break
            
            if not description:
                continue

            # 映射到项目所需的格式
            # 列基于 cve_2018-2020_y_train.csv
            entry = {
                'CVE_ID': cve_id,
                'Description': description,
                'cvssV3_vectorString': cvss_data.get('vectorString'),
                'cvssV3_attackVector': cvss_data.get('attackVector'),
                'cvssV3_attackComplexity': cvss_data.get('attackComplexity'),
                'cvssV3_privilegesRequired': cvss_data.get('privilegesRequired'),
                'cvssV3_userInteraction': cvss_data.get('userInteraction'),
                'cvssV3_scope': cvss_data.get('scope'),
                'cvssV3_confidentialityImpact': cvss_data.get('confidentialityImpact'),
                'cvssV3_integrityImpact': cvss_data.get('integrityImpact'),
                'cvssV3_availabilityImpact': cvss_data.get('availabilityImpact'),
                'cvssV3_baseScore': cvss_data.get('baseScore'),
                'cvssV3_baseSeverity': cvss_data.get('baseSeverity'),
                # 可利用性分数和影响分数通常是计算出来的，不总是在原始数据中
                # 我们可以尝试在 metrics 对象包装器中获取它们
                # 但目前我们让它们保持为 0.0 或如果需要则尝试找到它们
                # 'metrics' 列表项通常有 'exploitabilityScore' 和 'impactScore'
            }
            
            # 尝试从指标包装器（cvssData 外部）获取分数
            metric_wrapper = None
            if 'cvssMetricV31' in metrics:
                metric_wrapper = metrics['cvssMetricV31'][0]
            elif 'cvssMetricV30' in metrics:
                metric_wrapper = metrics['cvssMetricV30'][0]
                
            if metric_wrapper:
                entry['V3_exploitabilityScore'] = metric_wrapper.get('exploitabilityScore', 0.0)
                entry['V3_impactScore'] = metric_wrapper.get('impactScore', 0.0)
            
            # CWE (弱点)
            cwes = cve_item.get('weaknesses', [])
            cwe_list = []
            for weakness in cwes:
                for desc in weakness.get('description', []):
                    if desc.get('lang') == 'en':
                        cwe_list.append(desc.get('value'))
            
            entry['nb_CWE'] = len(cwe_list)
            entry['CWE1'] = cwe_list[0] if len(cwe_list) > 0 else 'None'
            entry['CWE2'] = cwe_list[1] if len(cwe_list) > 1 else 'None'
            
            parsed_data.append(entry)
            
        except Exception as e:
            # print(f"Error parsing item: {e}")
            continue
            
    return pd.DataFrame(parsed_data)

def main():
    sample_mode = False
    if len(sys.argv) > 1 and sys.argv[1] == '--sample':
        sample_mode = True
        
    print(f"开始更新年份: {YEARS} 的 CVE 数据")
    if sample_mode:
        print("采样模式已启用: 将仅获取一小部分数据。")
    print("注意: 如果没有 API 密钥，此过程可能需要很长时间。")
    
    # 下载数据
    raw_cves = download_cves(YEARS, sample_mode=sample_mode)
    print(f"已下载 {len(raw_cves)} 条原始 CVE 记录。")
    
    if not raw_cves:
        print("未下载到数据。退出。")
        return

    # 处理数据
    df = parse_cve_data(raw_cves)
    print(f"处理了 {len(df)} 条带有 CVSS v3 指标的有效 CVE 记录。")
    
    if df.empty:
        print("处理后没有有效数据。退出。")
        return

    # 保存完整数据集
    output_prefix = f"cve_{YEARS[0]}-{YEARS[-1]}"
    complete_path = os.path.join(OUTPUT_DIR, f"{output_prefix}_complete_dataset.csv")
    df.to_csv(complete_path, index=False)
    print(f"已保存完整数据集至 {complete_path}")
    
    # 分割为 训练集/测试集 (80/20)
    # 我们需要分割 X (特征) 和 y (标签)
    # 原始项目将 X 和 y 分为不同的文件
    
    X_cols = ['CVE_ID', 'Description']
    y_cols = [c for c in df.columns if c not in X_cols] # 所有其他列都是标签/元数据
    
    # 确保原始数据集中的所有 y_cols 都存在
    required_y_cols = [
        'cvssV3_vectorString', 'cvssV3_attackVector', 'cvssV3_attackComplexity',
        'cvssV3_privilegesRequired', 'cvssV3_userInteraction', 'cvssV3_scope',
        'cvssV3_confidentialityImpact', 'cvssV3_integrityImpact', 'cvssV3_availabilityImpact',
        'cvssV3_baseScore', 'cvssV3_baseSeverity', 'V3_exploitabilityScore',
        'V3_impactScore', 'nb_CWE', 'CWE1', 'CWE2'
    ]
    
    # 填充缺失列（如果有）
    for col in required_y_cols:
        if col not in df.columns:
            df[col] = 'None' if 'Score' not in col else 0.0
            
    X = df[X_cols]
    y = df[required_y_cols] # 重新排序以符合预期
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # 保存分割文件
    X_train.to_csv(os.path.join(OUTPUT_DIR, f"{output_prefix}_X_train.csv"), index=False)
    y_train.to_csv(os.path.join(OUTPUT_DIR, f"{output_prefix}_y_train.csv"), index=False)
    X_test.to_csv(os.path.join(OUTPUT_DIR, f"{output_prefix}_X_test.csv"), index=False)
    y_test.to_csv(os.path.join(OUTPUT_DIR, f"{output_prefix}_y_test.csv"), index=False)
    
    print("已保存 训练集/测试集 分割文件。")
    print(f"训练前缀: {os.path.join(OUTPUT_DIR, output_prefix)}")

if __name__ == "__main__":
    main()
