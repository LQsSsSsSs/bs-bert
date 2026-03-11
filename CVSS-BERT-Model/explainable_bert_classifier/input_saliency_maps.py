import torch
import torch.nn.functional as F
from torch.autograd import Variable
import re



def connectivity_tensor_computation(classifier, input_ids, attention_mask, verbose=False):
    """
    计算给定输入的连接性张量。连接性张量包含使用基于梯度的输入显著性方法获得的每个输入令牌的重要性得分。
    参数:
        classifier: 用于分类的 HuggingFace Transformers 模型。
        input_ids: BERT 模型 input_ids
        attention_mask: BERT 模型 attention_mask
    """
    input_embedding = classifier.get_input_embeddings()
    vocab_size = input_embedding.weight.shape[0]

    input_ids_one_hot = torch.nn.functional.one_hot(input_ids, num_classes=vocab_size)
    input_ids_one_hot = input_ids_one_hot.type(torch.float)
    input_ids_one_hot = Variable(input_ids_one_hot, requires_grad=True) # 允许计算关于输入的梯度
    if verbose == True:
        print("input grad variable:", input_ids_one_hot.grad)

    # 手动计算输入嵌入并通过 inputs_embeds 参数将其传递给模型
    inputs_embeds = torch.matmul(input_ids_one_hot, input_embedding.weight)
    embedding_dim = input_embedding.weight.shape[1]
    inputs_embeds = torch.mul(inputs_embeds, torch.cat([attention_mask.unsqueeze(1)]*embedding_dim, dim=1))


    outputs = classifier(inputs_embeds=inputs_embeds.unsqueeze(0), attention_mask=attention_mask.unsqueeze(0))


    if verbose == True:
        print("output logits:", outputs.logits)

    predicted_label = torch.max(F.softmax(outputs.logits, dim=1), dim=1)[1].item()
    if verbose == True:
        print("predicted label (after softmax):", predicted_label)
        print("score for predicted label (after softmax):", torch.max(F.softmax(outputs.logits, dim=1), dim=1)[0].item())
    outputs.logits[0][predicted_label].backward() # 计算 logit（预测值，得分最高的那一个）的梯度
    if verbose == True:
        print("input grad variable:", input_ids_one_hot.grad)                  # 关于输入

    connectivity_tensor = torch.linalg.norm(input_ids_one_hot.grad, dim=1)
    connectivity_tensor = connectivity_tensor/torch.max(connectivity_tensor)
    return connectivity_tensor



def top_k_tokens(text, tokenizer, classifier, k=5):
    """
    返回输入令牌（分词后的表示）的列表，以及前 k 个令牌的索引、值和连接性（重要性得分）。
    """
    text_encoding = tokenizer(text, truncation=True, padding=True, max_length=128)
    input_ids = torch.tensor(text_encoding['input_ids'])
    attention_mask = torch.tensor(text_encoding['attention_mask'])
    connectivity_tensor = connectivity_tensor_computation(classifier, input_ids, attention_mask)
    
    indices_sorted_by_connectivity = torch.argsort(connectivity_tensor, descending=True)
    input_tokens = tokenizer.convert_ids_to_tokens(list(input_ids))
    top_k_indices = indices_sorted_by_connectivity[:k]
    top_k_connectivity_weight = connectivity_tensor[top_k_indices]
    top_k_tokens = [input_tokens[i] for i in top_k_indices.tolist()]
    
    return {'input_tokens': input_tokens, 'top_k_tokens': top_k_tokens, 'top_k_indices': top_k_indices.tolist(), 'top_k_connectivity_weight': top_k_connectivity_weight.tolist()}





def print_texts_with_top_influential_words_in_bold(input_text_str, tokenizer, classifier, k=5):
    """
    以粗体打印包含前 k 个相关令牌（使用基于梯度的输入显著性方法确定）的文本。
    """
    # input_text_str: 对应于原始文本输入的 Python 字符串
    # top_k: 表示要考虑的前 k 个单词的最大数量的整数
    
    text_encoding = tokenizer(input_text_str, truncation=True, padding=True, max_length=128)
    input_ids = torch.tensor(text_encoding['input_ids'])
    attention_mask = torch.tensor(text_encoding['attention_mask'])
    
    connectivity_tensor = connectivity_tensor_computation(classifier, input_ids, attention_mask)
    input_tokens = tokenizer.convert_ids_to_tokens(list(input_ids))
    
    # input_tokens: 对应于输入的标记化表示的 Python 列表
    # connectivity_tensor: 包含 logit 相对于每个输入令牌的梯度的范数的 PyTorch 张量
    
    BOLD = '\033[1m'
    END = '\033[0m'
    
    output_str = input_text_str
    indices_sorted_by_connectivity = torch.argsort(connectivity_tensor, descending=True)
    top_indices_sorted = indices_sorted_by_connectivity[:k]
    
    for position, score in zip(top_indices_sorted,
                                     connectivity_tensor[top_indices_sorted]):
        
        if input_tokens[position.item()] in ['[UNK]', '[SEP]', '[PAD]', '[CLS]', '[MASK]']:
            continue
        
        # 查找包含所选单词（或令牌）的每个令牌的索引
        indices_all_matches = [i for i, x in enumerate(input_tokens) if re.sub('^##', '', input_tokens[position.item()]) in x]
        # 仅保留模型预期的位置（当同一单词多次出现时）。
        # 例如，如果选定的单词在描述中出现 3 次，并且算法主要受第二次出现的影响，则返回 1，第三次出现返回 2，依此类推
        position_of_the_intended_match = [i for i, x in enumerate(indices_all_matches) if x == position.item()]
        
        test_sub = re.escape(re.sub('^##', '', input_tokens[position.item()]))
        res = [i.start() for i in re.finditer(test_sub, output_str, re.IGNORECASE)]
        idx = position_of_the_intended_match[0]
        output_str = output_str[:res[idx]] + BOLD + output_str[res[idx]:res[idx]+len(test_sub)] + END + output_str[res[idx]+len(test_sub):]
        
    print(output_str)
    return output_str
    
