# lambda-functions/pano-mitre-worker/lambda_function.py
import os
import re
import json
import logging
from typing import Set, Optional
import numpy as np
from panorama_datamodel import db_session
from panorama_datamodel.models import DetectionRule, MitreTechnique, RuleMitreMapping

logger = logging.getLogger()
logger.setLevel(logging.INFO)

TECHNIQUE_PATTERNS = [
    re.compile(r'\bT\d{4}(?:\.\d{3})?\b', re.IGNORECASE),
    re.compile(r'attack\.t\d{4}(?:\.\d{3})?', re.IGNORECASE),
]

def normalize_technique_id(technique_id: str) -> Optional[str]:
    if not technique_id:
        return None
    
    technique_id = technique_id.upper().strip()
    technique_id = technique_id.replace('ATTACK.', '')
    
    if not technique_id.startswith('T'):
        technique_id = 'T' + technique_id
    
    if re.match(r'^T\d{4}(?:\.\d{3})?$', technique_id):
        return technique_id
    return None

def extract_explicit_techniques(rule: DetectionRule) -> Set[str]:
    techniques = set()
    
    # Check tags
    if rule.tags:
        for tag in rule.tags:
            if 'attack.t' in tag.lower():
                tech_id = tag.split('.')[-1]
                normalized = normalize_technique_id(tech_id)
                if normalized:
                    techniques.add(normalized)
    
    # Check metadata
    if rule.rule_metadata and isinstance(rule.rule_metadata, dict):
        for field in ['mitre_techniques', 'techniques', 'mitre_attack']:
            if field in rule.rule_metadata:
                values = rule.rule_metadata[field]
                if isinstance(values, list):
                    for tech in values:
                        normalized = normalize_technique_id(str(tech))
                        if normalized:
                            techniques.add(normalized)
                elif isinstance(values, str):
                    normalized = normalize_technique_id(values)
                    if normalized:
                        techniques.add(normalized)
    
    # Scan content
    search_text = f"{rule.name} {rule.description or ''} {rule.rule_content[:500] if rule.rule_content else ''}"
    for pattern in TECHNIQUE_PATTERNS:
        matches = pattern.findall(search_text)
        for match in matches:
            normalized = normalize_technique_id(match)
            if normalized:
                techniques.add(normalized)
    
    return techniques

def compute_text_embedding(text: str) -> np.ndarray:
    import boto3
    import onnxruntime as ort
    from transformers import AutoTokenizer
    
    model_path = '/tmp/model.onnx'
    if not os.path.exists(model_path):
        s3 = boto3.client('s3')
        s3.download_file(
            'panorama-ml-models-538269499906',
            'onnx/model_int8.onnx',
            model_path
        )
    
    tokenizer = AutoTokenizer.from_pretrained(
        'sentence-transformers/all-MiniLM-L6-v2',
        cache_dir='/tmp'
    )
    
    session = ort.InferenceSession(model_path)
    inputs = tokenizer(text, padding=True, truncation=True, max_length=128, return_tensors='np')
    outputs = session.run(None, {
        'input_ids': inputs['input_ids'],
        'attention_mask': inputs['attention_mask']
    })
    
    embeddings = outputs[0][0]
    mask = inputs['attention_mask'][0]
    mask_expanded = np.expand_dims(mask, -1)
    sum_embeddings = np.sum(embeddings * mask_expanded, axis=0)
    sum_mask = np.clip(mask_expanded.sum(axis=0), a_min=1e-9, a_max=None)
    return sum_embeddings / sum_mask

def load_technique_embeddings() -> dict:
    import boto3
    
    cache_path = '/tmp/technique_embeddings.json'
    if not os.path.exists(cache_path):
        s3 = boto3.client('s3')
        s3.download_file(
            'panorama-ml-models-538269499906',
            'onnx/technique_embeddings.json',
            cache_path
        )
    
    with open(cache_path) as f:
        data = json.load(f)
    return {k: np.array(v) for k, v in data.items()}

def cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    a_norm = a / np.linalg.norm(a)
    b_norm = b / np.linalg.norm(b)
    return float(np.dot(a_norm, b_norm))

def find_similar_techniques(text: str, min_similarity: float = 0.70) -> Set[str]:
    try:
        if not os.environ.get('USE_ML', 'false').lower() == 'true':
            return set()
            
        embedding = compute_text_embedding(text)
        technique_embeddings = load_technique_embeddings()
        
        # Calculate similarities for all techniques
        similarities = []
        for tech_id, tech_embedding in technique_embeddings.items():
            similarity = cosine_similarity(embedding, tech_embedding)
            if similarity > min_similarity:
                similarities.append((tech_id, similarity))
        
        # Sort and return top 3
        similarities.sort(key=lambda x: x[1], reverse=True)
        return {tech_id for tech_id, _ in similarities[:3]}
        
    except Exception as e:
        logger.debug(f"ML not available: {e}")
        return set()

def lambda_handler(event, context):
    chunk_id = event['chunk_id']
    rule_ids = event['rule_ids']
    
    logger.info(f"Processing chunk {chunk_id} with {len(rule_ids)} rules")
    
    with db_session() as session:
        # Load valid techniques once
        techniques = session.query(MitreTechnique).filter(
            MitreTechnique.is_deprecated == False
        ).all()
        valid_techniques = {t.technique_id: t for t in techniques}
        
        # Query rules for this chunk
        rules = session.query(DetectionRule).filter(
            DetectionRule.id.in_(rule_ids)
        ).all()
        
        mappings_created = 0
        mappings_skipped = 0
        
        for rule in rules:
            # Extract explicit techniques first
            found_techniques = extract_explicit_techniques(rule)
            
            # Use ML if we found few explicit techniques
            if len(found_techniques) < 2 and os.environ.get('USE_ML', 'false').lower() == 'true':
                # Build focused text for ML analysis
                text_parts = [rule.name]
                if rule.description:
                    text_parts.append(rule.description[:200])
                if rule.tags:
                    # Include attack-related tags for context
                    attack_tags = [t for t in rule.tags if 'attack' in t.lower()]
                    text_parts.extend(attack_tags)
                
                rule_text = ' '.join(text_parts)
                ml_techniques = find_similar_techniques(rule_text)
                found_techniques.update(ml_techniques)
            
            # Create mappings for found techniques
            for technique_id in found_techniques:
                if technique_id in valid_techniques:
                    technique = valid_techniques[technique_id]
                    
                    # Check for existing mapping
                    existing = session.query(RuleMitreMapping).filter_by(
                        rule_id=rule.id,
                        technique_id=technique.id
                    ).first()
                    
                    if not existing:
                        mapping = RuleMitreMapping(
                            rule_id=rule.id,
                            technique_id=technique.id,
                            mapping_confidence=1.0,  # Default for backward compatibility
                            mapping_source='enricher'  # Default for backward compatibility
                        )
                        session.add(mapping)
                        mappings_created += 1
                    else:
                        mappings_skipped += 1
        
        session.commit()
        logger.info(f"Chunk {chunk_id}: Created {mappings_created} mappings, skipped {mappings_skipped} existing")
    
    return {
        'chunk_id': chunk_id,
        'rules_processed': len(rules),
        'mappings_created': mappings_created,
        'mappings_skipped': mappings_skipped
    }