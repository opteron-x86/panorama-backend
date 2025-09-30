# lambda-functions/pano-mitre-enricher/onnx_helper.py
import json
import numpy as np
import boto3

class ONNXEnricher:
    def __init__(self):
        self.s3 = boto3.client('s3')
        self.embeddings = None
        self.onnx_session = None
        self.tokenizer = None
        self._load_embeddings()
    
    def _load_embeddings(self):
        self.s3.download_file(
            'panorama-ml-models-538269499906',
            'onnx/technique_embeddings.json',
            '/tmp/technique_embeddings.json'
        )
        with open('/tmp/technique_embeddings.json') as f:
            data = json.load(f)
        self.embeddings = {k: np.array(v) for k, v in data.items()}
    
    def _init_model(self):
        if self.onnx_session:
            return
            
        self.s3.download_file(
            'panorama-ml-models-538269499906',
            'onnx/model_int8.onnx',
            '/tmp/model.onnx'
        )
        
        import onnxruntime as ort
        from transformers import AutoTokenizer
        
        self.onnx_session = ort.InferenceSession('/tmp/model.onnx')
        self.tokenizer = AutoTokenizer.from_pretrained(
            'sentence-transformers/all-MiniLM-L6-v2',
            cache_dir='/tmp'
        )
    
    def get_embedding(self, text: str) -> np.ndarray:
        self._init_model()
        inputs = self.tokenizer(
            text,
            padding=True,
            truncation=True,
            max_length=128,
            return_tensors='np'
        )
        
        outputs = self.onnx_session.run(None, {
            'input_ids': inputs['input_ids'],
            'attention_mask': inputs['attention_mask']
        })
        
        embeddings = outputs[0][0]
        mask = inputs['attention_mask'][0]
        mask_expanded = np.expand_dims(mask, -1)
        sum_embeddings = np.sum(embeddings * mask_expanded, axis=0)
        sum_mask = np.clip(mask_expanded.sum(axis=0), a_min=1e-9, a_max=None)
        return sum_embeddings / sum_mask
    
    def find_techniques(self, rule_text: str, threshold: float = 0.65):
        rule_embedding = self.get_embedding(rule_text)
        rule_norm = rule_embedding / np.linalg.norm(rule_embedding)
        
        scores = []
        for tech_id, tech_embedding in self.embeddings.items():
            tech_norm = tech_embedding / np.linalg.norm(tech_embedding)
            similarity = float(np.dot(rule_norm, tech_norm))
            
            if similarity > threshold:
                scores.append((tech_id, similarity))
        
        return sorted(scores, key=lambda x: x[1], reverse=True)[:5]