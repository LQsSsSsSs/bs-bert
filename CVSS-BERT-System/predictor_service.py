import torch
import os
import pickle
import numpy as np
from transformers import BertTokenizerFast, BertForSequenceClassification
from peft import PeftModel
from sklearn.preprocessing import LabelEncoder
from cvss import CVSS3
from deep_translator import GoogleTranslator
from langdetect import detect, LangDetectException
import streamlit as st
import requests
from bs4 import BeautifulSoup
import re

# Configuration
MODEL_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'CVSS-BERT-Model', 'bert-classifier'))
BASE_MODEL = "prajjwal1/bert-small"

# Mapping from our metric names to CVSS vector abbreviations
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

# Mapping for value abbreviations
VALUE_MAPPING = {
    # Attack Vector
    "NETWORK": "N", "ADJACENT_NETWORK": "A", "LOCAL": "L", "PHYSICAL": "P",
    # Attack Complexity
    "LOW": "L", "HIGH": "H",
    # Privileges Required
    "NONE": "N", "LOW": "L", "HIGH": "H",
    # User Interaction
    "NONE": "N", "REQUIRED": "R",
    # Scope
    "UNCHANGED": "U", "CHANGED": "C",
    # CIA Impact
    "NONE": "N", "LOW": "L", "HIGH": "H"
}

@st.cache_resource
class CVSSPredictor:
    def __init__(self):
        self.device = torch.device('cuda') if torch.cuda.is_available() else torch.device('cpu')
        # Try to load tokenizer from local path first
        local_model_path = os.path.abspath(os.path.join(MODEL_DIR, "prajjwal1", "bert-small"))
        if os.path.exists(local_model_path):
            print(f"Loading tokenizer from local: {local_model_path}")
            self.tokenizer = BertTokenizerFast.from_pretrained(local_model_path, local_files_only=True)
        else:
            self.tokenizer = BertTokenizerFast.from_pretrained(BASE_MODEL)
        self.models = {}
        self.encoders = {}
        self.translator = GoogleTranslator(source='auto', target='en')
        self.zh_translator = GoogleTranslator(source='auto', target='zh-CN')
        self.cwe_cache = {}
        
        self._load_all_models()
        
    def _load_all_models(self):
        targets = list(METRIC_MAPPING.keys()) + ["CWE1"]
        for metric in targets:
            metric_path = os.path.join(MODEL_DIR, metric)
            model_path = os.path.join(metric_path, "model")
            label_path = os.path.join(metric_path, "label.txt")
            
            if not os.path.exists(model_path) or not os.path.exists(label_path):
                continue
                
            # 1. Load Label Encoder
            with open(label_path, "rb") as f:
                classes = pickle.load(f)
                le = LabelEncoder()
                le.classes_ = classes
                self.encoders[metric] = le
                
            # 2. Load Model (Base + LoRA)
            num_labels = len(classes)
            
            # Try loading base model from local path first to avoid HF connection
            local_base_path = os.path.abspath(os.path.join(MODEL_DIR, "prajjwal1", "bert-small"))
            try:
                if os.path.exists(local_base_path):
                     base_model = BertForSequenceClassification.from_pretrained(local_base_path, num_labels=num_labels)
                else:
                     base_model = BertForSequenceClassification.from_pretrained(BASE_MODEL, num_labels=num_labels)
            except Exception as e:
                print(f"Warning: Could not download base model: {e}. Trying local cache only.")
                base_model = BertForSequenceClassification.from_pretrained(BASE_MODEL, num_labels=num_labels, local_files_only=True)

            model = PeftModel.from_pretrained(base_model, model_path)
            model.to(self.device)
            model.eval()
            self.models[metric] = model
            
    def detect_and_translate(self, text):
        """
        Detect language and translate to English if needed.
        Returns: (original_lang, translated_text)
        """
        try:
            lang = detect(text)
        except LangDetectException:
            lang = 'unknown'
            
        if lang != 'en':
            try:
                translated = self.translator.translate(text)
                return lang, translated
            except Exception as e:
                return lang, text # Return original if translation fails
        return lang, text

    def translate_to_chinese(self, text):
        """Translate text to Chinese"""
        try:
            return self.zh_translator.translate(text)
        except Exception:
            return text

    def get_cwe_info(self, cwe_id):
        """
        Fetch CWE title and description from MITRE website.
        cwe_id: e.g., 'CWE-79'
        """
        if not cwe_id or cwe_id == 'None' or cwe_id == 'NVD-CWE-noinfo':
            return None
            
        if cwe_id in self.cwe_cache:
            return self.cwe_cache[cwe_id]
            
        try:
            # Extract ID number
            match = re.search(r'\d+', cwe_id)
            if not match:
                return None
            id_num = match.group(0)
            
            url = f"https://cwe.mitre.org/data/definitions/{id_num}.html"
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
            
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                
                # Get Title
                title_elem = soup.find('h2')
                title = title_elem.text.strip() if title_elem else cwe_id
                # Remove "CWE-ID : Name" prefix if present to get clean name
                if ":" in title:
                    title = title.split(":", 1)[1].strip()
                
                # Get Description
                desc_div = soup.find('div', id='Description')
                description = ""
                if desc_div:
                    desc_body = desc_div.find('div', class_='detail')
                    if desc_body:
                        description = desc_body.text.strip()
                
                # Translate to Chinese
                zh_title = self.translate_to_chinese(title)
                # zh_desc = self.translate_to_chinese(description) # User doesn't want translated desc for now
                
                info = {
                    "title": title, # English Title
                    "zh_title": zh_title, # Chinese Title
                    "description": description, # English Description
                    "url": url
                }
                
                self.cwe_cache[cwe_id] = info
                return info
                
        except Exception as e:
            print(f"Error fetching CWE info: {e}")
            
        return None

    def predict(self, text):
        inputs = self.tokenizer(text, truncation=True, padding=True, max_length=128, return_tensors="pt")
        inputs = {k: v.to(self.device) for k, v in inputs.items()}
        
        vector_components = []
        detailed_results = {}
        cwe_result = None
        
        targets = list(METRIC_MAPPING.keys()) + ["CWE1"]
        for metric in targets:
            short_name = METRIC_MAPPING.get(metric, metric)
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
            
            if metric == "CWE1":
                # Get extra info for CWE
                cwe_info = self.get_cwe_info(pred_label)
                
                cwe_result = {
                    "label": pred_label,
                    "confidence": confidence,
                    "info": cwe_info
                }
                continue

            detailed_results[metric] = {
                "label": pred_label,
                "confidence": confidence
            }
            
            # Map to CVSS vector format
            short_value = VALUE_MAPPING.get(pred_label, pred_label[0]) 
            vector_components.append(f"{short_name}:{short_value}")
            
        # Construct Vector String
        vector_string = "CVSS:3.1/" + "/".join(vector_components)
        
        # Calculate Score
        base_score = 0.0
        severity = "Unknown"
        try:
            c = CVSS3(vector_string)
            base_score = c.base_score
            severity = c.severities()[0]
        except Exception:
            pass
            
        return {
            "vector": vector_string,
            "base_score": base_score,
            "severity": severity,
            "details": detailed_results,
            "cwe": cwe_result
        }
