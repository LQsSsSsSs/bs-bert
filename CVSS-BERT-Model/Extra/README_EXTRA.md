# 📂 Extra 文件夹说明文档

`Extra` 文件夹包含了一系列 Jupyter Notebooks 和辅助数据，主要用于 **CVE 数据的原始清洗、预处理、数据集构建以及模型初步实验**。这些脚本是整个项目的数据基石，用于生成 `CVSS-BERT-Model/data/` 目录下最终使用的 CSV 训练数据。

---

## 📑 文件内容详解

### 1. 数据处理核心脚本
*   **`cve_data_cleaning_and_dataset_generation.ipynb`**
    *   **作用**: 从原始的 NVD JSON 数据源中提取 CVE 条目，清洗文本（去除特殊字符、标准化），并提取 CVSS v3.1 向量信息。
    *   **输出**: 初步清洗后的 DataFrame 或 CSV 文件。
*   **`train_test_dataset_generation.ipynb`**
    *   **作用**: 将清洗后的全量数据按照一定比例（如 8:2）划分为训练集 (`X_train.csv`, `y_train.csv`) 和测试集 (`X_test.csv`, `y_test.csv`)。
    *   **重要性**: 它是生成当前项目 `data/` 目录内容的源头。
*   **`final_multiyear_cve_dataset.ipynb`**
    *   **作用**: 用于合并多年份（如 2023, 2024, 2025）的 CVE 数据，构建一个时间跨度更大的综合数据集，以提高模型的泛化能力。

### 2. 实验与验证脚本
*   **`cvssV3_vector_string_reconstruction_test_set.ipynb`**
    *   **作用**: 验证脚本。用于检查从各个 CVSS 指标（AV, AC, PR 等）重组回完整的 CVSS 向量字符串（如 `CVSS:3.1/AV:N/AC:L...`）的准确性，确保逻辑无误。

### 3. 指标分类文件夹
*   包含 `Attack_Vector/`, `Attack_Complexity/`, `Privileges_Required/` 等 8 个子文件夹。
*   **作用**: 存放针对每个特定 CVSS 指标的独立实验数据、临时模型权重或分析图表。

---

## 🛠️ 如何调用与使用

这些文件均为 `.ipynb` 格式，建议使用 **Jupyter Notebook** 或 **VS Code** 打开运行。

### 前置条件
确保已安装 Jupyter 环境：
```bash
pip install jupyterlab pandas numpy
```

### 典型工作流

如果您想**从头构建一个新的数据集**（例如添加了 2026 年的新数据），请按以下顺序执行：

1.  **准备数据**: 下载最新的 NVD JSON 数据包。
2.  **数据清洗**:
    *   打开并运行 `cve_data_cleaning_and_dataset_generation.ipynb`。
    *   修改输入路径指向您的新 JSON 文件。
3.  **合并年份 (可选)**:
    *   如果有多年的数据，运行 `final_multiyear_cve_dataset.ipynb` 进行合并。
4.  **生成训练集**:
    *   运行 `train_test_dataset_generation.ipynb`。
    *   脚本运行结束后，生成的 `_X_train.csv` 等文件会自动保存在 `data/` 目录下（可能需要手动移动或修改输出路径）。
5.  **开始训练**:
    *   回到 `CVSS-BERT-Model` 根目录，运行 `python train_all_metrics.py` 使用新数据训练模型。

---
**注意**: 如果您只关注使用现有的预训练模型进行预测，**无需运行**这些 Notebooks。
