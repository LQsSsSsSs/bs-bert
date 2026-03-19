import torch
import torch.nn.functional as F
import transformers
from transformers import BertForSequenceClassification, Trainer, TrainingArguments, EarlyStoppingCallback
from peft import get_peft_model, LoraConfig, TaskType
import os

class BertClassifier():
    """
    使用 Hugging Face Trainer 和 LoRA 的 BERT 分类器对象。
    """
    
    def __init__(self, model_name='prajjwal1/bert-small', num_labels=2, **kwargs):
        """
        初始化用于序列分类任务的 BERT 模型
        """
        self.device = torch.device('cuda') if torch.cuda.is_available() else torch.device('cpu')
        self.num_labels = num_labels
        self.model_name = model_name
        
        # 加载基础模型
        self.model = BertForSequenceClassification.from_pretrained(model_name, num_labels=num_labels, **kwargs)
        
        # 配置 LoRA
        peft_config = LoraConfig(
            task_type=TaskType.SEQ_CLS,
            inference_mode=False,
            r=8,
            lora_alpha=32,
            lora_dropout=0.1,
            target_modules=["query", "value"] # BERT 的目标注意力层
        )
        
        # 应用 LoRA
        self.model = get_peft_model(self.model, peft_config)
        self.model.print_trainable_parameters()
        self.model.to(self.device)

    def fit(self, train_dataset, val_dataset, output_dir='./results', epochs=10, batch_size=16):
        """
        使用 Hugging Face Trainer 训练模型。
        """
        
        training_args = TrainingArguments(
            output_dir=output_dir,
            num_train_epochs=epochs,
            per_device_train_batch_size=batch_size,
            per_device_eval_batch_size=batch_size,
            warmup_steps=500,
            weight_decay=0.01,
            logging_dir=f'{output_dir}/logs',
            logging_steps=10,
            eval_strategy="epoch",
            save_strategy="epoch",
            load_best_model_at_end=True,
            metric_for_best_model="accuracy",
            fp16=True, # 启用混合精度 (FP16)
            dataloader_num_workers=0, # 禁用数据加载的多进程
            report_to="none",
            disable_tqdm=True # 禁用内部进度条以避免冲突
        )
        
        def compute_metrics(eval_pred):
            logits, labels = eval_pred
            predictions = np.argmax(logits, axis=-1)
            return {"accuracy": (predictions == labels).mean()}
        
        import numpy as np
        
        trainer = Trainer(
            model=self.model,
            args=training_args,
            train_dataset=train_dataset,
            eval_dataset=val_dataset,
            compute_metrics=compute_metrics,
            callbacks=[EarlyStoppingCallback(early_stopping_patience=3)]
        )
        
        trainer.train()
        return trainer

    def predict(self, batch_tokenized):
        """
        预测一批样本的标签
        """
        self.model.eval()
        input_ids = batch_tokenized['input_ids'].to(self.device)
        attention_mask = batch_tokenized['attention_mask'].to(self.device)
        
        with torch.no_grad():
            outputs = self.model(input_ids, attention_mask=attention_mask)
        
        predicted_labels = torch.argmax(outputs.logits, dim=1)
        predicted_scores = torch.max(F.softmax(outputs.logits, dim=1), dim=1)[0]

        return {'predicted_labels': predicted_labels, 'predicted_scores': predicted_scores}
