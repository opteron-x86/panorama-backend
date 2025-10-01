# lambda-functions/pano-mitre-worker/lambda_function.py
import os
import re
import json
import logging
from typing import Set, Dict, Optional, Tuple
import numpy as np
from panorama_datamodel import db_session
from panorama_datamodel.models import DetectionRule, MitreTechnique, RuleMitreMapping

logger = logging.getLogger()
logger.setLevel(logging.INFO)

import onnxruntime as ort
from transformers import AutoTokenizer

MODEL_PATH = '/opt/ml/model.onnx'
EMBEDDINGS_PATH = '/opt/ml/technique_embeddings.json'

ONNX_SESSION = None
TOKENIZER = None
TECHNIQUE_EMBEDDINGS = None

def init_ml():
    global ONNX_SESSION, TOKENIZER, TECHNIQUE_EMBEDDINGS
    
    if ONNX_SESSION is None:
        ONNX_SESSION = ort.InferenceSession(MODEL_PATH)
        TOKENIZER = AutoTokenizer.from_pretrained(
            'sentence-transformers/all-MiniLM-L6-v2',
            cache_dir='/tmp'
        )
        with open(EMBEDDINGS_PATH) as f:
            data = json.load(f)
        TECHNIQUE_EMBEDDINGS = {k: np.array(v) for k, v in data.items()}
        logger.info("ML models initialized")

TECHNIQUE_PATTERNS = [
    re.compile(r'\bT\d{4}(?:\.\d{3})?\b', re.IGNORECASE),
    re.compile(r'attack\.t\d{4}(?:\.\d{3})?', re.IGNORECASE),
]

def normalize_technique_id(technique_id: str) -> Optional[str]:
    if not technique_id:
        return None
    
    technique_id = technique_id.upper().strip().replace('ATTACK.', '')
    if not technique_id.startswith('T'):
        technique_id = 'T' + technique_id
    
    if re.match(r'^T\d{4}(?:\.\d{3})?$', technique_id):
        return technique_id
    return None

def extract_explicit_techniques(rule: DetectionRule) -> Set[str]:
    techniques = set()
    
    search_text = rule.name or ""
    if rule.description:
        search_text += f" {rule.description}"
    if rule.tags:
        search_text += f" {' '.join(rule.tags)}"
    if rule.rule_content:
        search_text += f" {rule.rule_content[:1000]}"
    
    for pattern in TECHNIQUE_PATTERNS:
        matches = pattern.findall(search_text)
        for match in matches:
            normalized = normalize_technique_id(match)
            if normalized:
                techniques.add(normalized)
    
    if rule.rule_metadata and isinstance(rule.rule_metadata, dict):
        for key, value in rule.rule_metadata.items():
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, str) and re.match(r'T\d{4}', item):
                        normalized = normalize_technique_id(item)
                        if normalized:
                            techniques.add(normalized)
            elif isinstance(value, str) and re.match(r'T\d{4}', value):
                normalized = normalize_technique_id(value)
                if normalized:
                    techniques.add(normalized)
    
    return techniques

def compute_text_embedding(text: str) -> Optional[np.ndarray]:
    try:
        init_ml()
        inputs = TOKENIZER(text, padding=True, truncation=True, max_length=128, return_tensors='np')
        outputs = ONNX_SESSION.run(None, {
            'input_ids': inputs['input_ids'],
            'attention_mask': inputs['attention_mask']
        })
        
        embeddings = outputs[0][0]
        mask = inputs['attention_mask'][0]
        mask_expanded = np.expand_dims(mask, -1)
        sum_embeddings = np.sum(embeddings * mask_expanded, axis=0)
        sum_mask = np.clip(mask_expanded.sum(axis=0), a_min=1e-9, a_max=None)
        return sum_embeddings / sum_mask
    except Exception as e:
        logger.error(f"Embedding computation failed: {e}")
        return None

def find_similar_techniques(text: str, threshold: float = 0.65) -> Dict[str, float]:
    """Returns dict of technique_id -> similarity_score"""
    init_ml()
    embedding = compute_text_embedding(text)
    if embedding is None or TECHNIQUE_EMBEDDINGS is None:
        return {}
    
    embedding_norm = embedding / np.linalg.norm(embedding)
    
    similarities = []
    for tech_id, tech_embedding in TECHNIQUE_EMBEDDINGS.items():
        tech_norm = tech_embedding / np.linalg.norm(tech_embedding)
        similarity = float(np.dot(embedding_norm, tech_norm))
        if similarity > threshold:
            similarities.append((tech_id, similarity))
    
    similarities.sort(key=lambda x: x[1], reverse=True)
    return {tech_id: score for tech_id, score in similarities[:5]}

def lambda_handler(event, context):
    chunk_id = event['chunk_id']
    rule_ids = event['rule_ids']
    
    logger.info(f"Processing chunk {chunk_id} with {len(rule_ids)} rules")
    
    use_ml = os.environ.get('USE_ML', 'false').lower() == 'true'
    ml_threshold = float(os.environ.get('ML_THRESHOLD', '0.65'))
    
    with db_session() as session:
        techniques = session.query(MitreTechnique).filter(
            MitreTechnique.is_deprecated == False
        ).all()
        valid_techniques = {t.technique_id: t for t in techniques}
        
        rules = session.query(DetectionRule).filter(
            DetectionRule.id.in_(rule_ids)
        ).all()
        
        mappings_created = 0
        rules_with_explicit = 0
        rules_with_ml = 0
        rules_without_techniques = 0
        
        for rule in rules:
            # Track technique sources
            explicit_techniques = extract_explicit_techniques(rule)
            ml_techniques = {}  # technique_id -> confidence score
            
            if explicit_techniques:
                rules_with_explicit += 1
            elif use_ml:
                rule_text = f"{rule.name} {rule.description or ''}"
                if rule.tags:
                    rule_text += f" {' '.join(rule.tags[:10])}"
                
                ml_techniques = find_similar_techniques(rule_text, ml_threshold)
                if ml_techniques:
                    rules_with_ml += 1
            
            # Combine all techniques
            all_techniques = explicit_techniques.union(ml_techniques.keys())
            
            if not all_techniques:
                rules_without_techniques += 1
                continue
            
            # Create mappings with proper metadata
            for technique_id in all_techniques:
                if technique_id in valid_techniques:
                    technique = valid_techniques[technique_id]
                    
                    existing = session.query(RuleMitreMapping).filter_by(
                        rule_id=rule.id,
                        technique_id=technique.id
                    ).first()
                    
                    if not existing:
                        # Determine source and confidence
                        if technique_id in explicit_techniques:
                            enrichment_method = 'regex'
                            ml_confidence = None
                        else:
                            enrichment_method = 'ml'
                            ml_confidence = ml_techniques.get(technique_id, 0.65)
                        
                        mapping = RuleMitreMapping(
                            rule_id=rule.id,
                            technique_id=technique.id,
                            source='ml' if technique_id in ml_techniques else 'regex',
                            confidence=ml_techniques.get(technique_id) if technique_id in ml_techniques else None
                        )
                        session.add(mapping)
                        mappings_created += 1
        
        session.commit()
        
        logger.info(f"Chunk {chunk_id}: {mappings_created} mappings created, "
                   f"{rules_with_explicit} explicit, {rules_with_ml} ML, "
                   f"{rules_without_techniques} no techniques")
    
    return {
        'chunk_id': chunk_id,
        'rules_processed': len(rules),
        'mappings_created': mappings_created,
        'rules_with_explicit': rules_with_explicit,
        'rules_with_ml': rules_with_ml,
        'rules_without_techniques': rules_without_techniques
    }