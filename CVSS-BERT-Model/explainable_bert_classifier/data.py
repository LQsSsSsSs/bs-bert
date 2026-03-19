import torch
from sklearn.preprocessing import LabelEncoder
import pickle
from transformers import BertTokenizerFast
import numpy as np


def fit_transform_LabelEncoder(labels, save=False, filename='label.txt'):
    """
    将目标标签编码为 0 到 n_classes-1 之间的值。拟合标签编码器并返回编码后的标签。
    参数:
        labels: 要编码的分类标签列表
        save (默认 False): 如果为 True，则保存包含每个类标签的列表。
        filename: 保存文件的路径。
    """
    le = LabelEncoder()
    le.fit(labels)
    NUM_CLASSES = len(le.classes_)
    print("类别总数:", NUM_CLASSES)
    print("类别:", le.classes_)

    if save==True:
        with open(filename, "wb") as f:
            pickle.dump(le.classes_, f)

    encoded_train_labels = le.transform(labels)
    
    return encoded_train_labels


def train_test_LabelEncoder(train_labels, test_labels, save=False, filename='label.txt'):
    """
    将目标标签编码为 0 到 n_classes-1 之间的值。拟合标签编码器并返回训练集上的编码标签。
    同时返回测试集上的编码标签。
    参数:
        train_labels: 要编码的分类训练标签列表
        test_labels: 要编码的分类测试标签列表
        save (默认 False): 如果为 True，则保存包含每个类标签的列表。
        filename: 保存文件的路径。
    """
    le = LabelEncoder()
    le.fit(train_labels)
    NUM_CLASSES = len(le.classes_)
    print("类别总数:", NUM_CLASSES)
    print("类别:", le.classes_)

    if save==True:
        with open(filename, "wb") as f:
            pickle.dump(le.classes_, f)

    encoded_train_labels = le.transform(train_labels)
    encoded_test_labels = le.transform(test_labels)
    
    return encoded_train_labels, encoded_test_labels



def tokenizer(tokenizer_name='prajjwal1/bert-small', **kwargs):
    """
    初始化分词器。
    """
    return BertTokenizerFast.from_pretrained(tokenizer_name, **kwargs)


def split_dataset(dataset, labels, encoded_labels, tokenizer, val_proportion=0.2, shuffle=True):
    """
    分割数据集、标签、编码标签，并返回两个数据集对象：一个用于训练，另一个用于验证/测试。
    参数:
        dataset: 要分割的数据集
        labels: 要分割的标签
        encoded_labels: 对应的要分割的编码标签
        tokenizer: 用于分词的分词器
        val_proportion (默认=0.2): 用于验证数据集的数据比例
        shuffle (默认=True): 如果为 True，则在分割数据前进行打乱
        
    """
    dataset_size = dataset.shape[0]
    #print("size: ", dataset_size)
    indices = np.arange(dataset_size)
    if shuffle==True:
        np.random.shuffle(indices)
    #print("indices: ", indices.shape, indices)
    split_index = int(val_proportion*dataset_size)
    val_indices = indices[:split_index]
    train_indices = indices[split_index:]
    #print("train indices: ", train_indices.shape, train_indices)
    #print("val indices: ", val_indices.shape, val_indices)
    number_of_common_indices = [1 for i in val_indices if i in train_indices]
    #print(number_of_common_indices)
    
    X_train = dataset.iloc[train_indices,:]
    X_val = dataset.iloc[val_indices,:]
    
    train_labels = labels[train_indices]
    val_labels = labels[val_indices]
    
    encoded_train_labels = encoded_labels[train_indices]
    encoded_val_labels = encoded_labels[val_indices]

    train_encodings = tokenizer(X_train.loc[:,"Description"].tolist(), truncation=True, padding=True, max_length=128)
    val_encodings = tokenizer(X_val.loc[:,"Description"].tolist(), truncation=True, padding=True, max_length=128)
    
    
    train_dataset = CVEDataset(X_train, train_encodings, train_labels, encoded_train_labels)
    val_dataset = CVEDataset(X_val, val_encodings, val_labels, encoded_val_labels)
    
    return train_dataset, val_dataset


class CVEDataset(torch.utils.data.Dataset):
    """
    CVEDataset 对象，用于处理 CVE 漏洞描述数据，以便使用 PyTorch 进行训练和测试
    """
    def __init__(self, X, encodings, labels, encoded_labels):
        """
        参数:
        X: CVE 漏洞描述数据集。必须包含两列："CVE_ID" 和实际的 "Description"。
        encodings: X 中包含的描述的分词表示
        labels: X 中包含的描述的文本形式标签
        encoded_labels: 对应的编码标签
        """
        self.cve_id = X.loc[:,"CVE_ID"].tolist()
        self.texts = X.loc[:,"Description"].tolist()
        self.encodings = encodings
        self.labels = labels.tolist()
        self.encoded_labels = encoded_labels

    def __getitem__(self, idx):
        item = {key: torch.tensor(val[idx]) for key, val in self.encodings.items()}
        item['labels'] = torch.tensor(self.encoded_labels[idx])
        item['text_labels'] = self.labels[idx]
        item['encoded_labels'] = torch.tensor(self.encoded_labels[idx])
        item['CVE_ID'] = self.cve_id[idx]
        item['vulnerability_description'] = self.texts[idx]
        
        return item

    def __len__(self):
        return len(self.labels)
