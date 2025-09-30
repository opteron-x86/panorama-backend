# lambda-functions/pano-ml-enricher/lambda_function.py
import json
import pickle
import numpy as np
from typing import List, Tuple, Dict, Any
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity

from panorama_datamodel import db_session
from panorama_datamodel.models import MitreTechnique, DetectionRule, RuleMitreMapping

class SemanticMitreEnricher:
    def __init__(self):
        self.encoder = self._load_model_from_s3()
        self.technique_embeddings = self._load_embeddings_from_s3()
        self.technique_metadata = self._load_technique_metadata()
        
    def _load_model_from_s3(self):
        # Use smaller model for Lambda constraints
        # Download to /tmp/ on cold start
        import boto3
        import tarfile
        
        s3 = boto3.client('s3')
        model_path = '/tmp/sentence_transformer'
        
        if not os.path.exists(model_path):
            s3.download_file(
                'panorama-ml-models',
                'models/all-MiniLM-L6-v2.tar.gz',
                '/tmp/model.tar.gz'
            )
            with tarfile.open('/tmp/model.tar.gz', 'r:gz') as tar:
                tar.extractall('/tmp/')
        
        return SentenceTransformer(model_path)
    
    def process_rule(self, rule: DetectionRule) -> List[Tuple[str, float]]:
        rule_text = f"{rule.name} {rule.description} {rule.rule_content[:500]}"
        rule_embedding = self.encoder.encode(rule_text)
        
        similarities = {}
        for tech_id, tech_embedding in self.technique_embeddings.items():
            score = cosine_similarity(
                rule_embedding.reshape(1, -1),
                tech_embedding.reshape(1, -1)
            )[0][0]
            
            if score > 0.65:  # Threshold tuned on validation set
                similarities[tech_id] = float(score)
        
        return sorted(similarities.items(), key=lambda x: x[1], reverse=True)[:5]