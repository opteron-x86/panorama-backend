"""
MITRE ATT&CK Enricher
"""
import os
import re
import logging
from typing import Set, List, Dict, Any, Optional
from datetime import datetime

import numpy as np
from panorama_datamodel import db_session
from panorama_datamodel.models import DetectionRule, MitreTechnique, RuleMitreMapping

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Regex patterns for explicit technique extraction
TECHNIQUE_PATTERNS = [
    re.compile(r'\bT\d{4}(?:\.\d{3})?\b', re.IGNORECASE),
    re.compile(r'attack\.t\d{4}(?:\.\d{3})?', re.IGNORECASE),
]

def normalize_technique_id(technique_id: str) -> Optional[str]:
    """Normalize technique ID to standard format (T1234 or T1234.001)"""
    if not technique_id:
        return None
    
    technique_id = technique_id.upper().strip()
    technique_id = technique_id.replace('ATTACK.', '')
    
    if not technique_id.startswith('T'):
        technique_id = 'T' + technique_id
    
    # Validate format
    if re.match(r'^T\d{4}(?:\.\d{3})?$', technique_id):
        return technique_id
    return None

def extract_explicit_techniques(rule: DetectionRule) -> Set[str]:
    """Extract explicitly mentioned technique IDs from rule"""
    techniques = set()
    
    # Check tags for attack.* patterns
    if rule.tags:
        for tag in rule.tags:
            if 'attack.t' in tag.lower():
                tech_id = tag.split('.')[-1]
                normalized = normalize_technique_id(tech_id)
                if normalized:
                    techniques.add(normalized)
    
    # Check metadata if structured
    if rule.rule_metadata and isinstance(rule.rule_metadata, dict):
        # Look for common metadata fields
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
    
    # Scan rule content for T#### patterns
    search_text = f"{rule.name} {rule.description or ''} {rule.rule_content[:500] if rule.rule_content else ''}"
    for pattern in TECHNIQUE_PATTERNS:
        matches = pattern.findall(search_text)
        for match in matches:
            normalized = normalize_technique_id(match)
            if normalized:
                techniques.add(normalized)
    
    return techniques

def find_similar_techniques(text: str, min_similarity: float = 0.65) -> List[str]:
    """Find techniques using semantic similarity"""
    try:
        embedding = compute_text_embedding(text)
        technique_embeddings = load_technique_embeddings()
        
        similarities = []
        for tech_id, tech_embedding in technique_embeddings.items():
            similarity = cosine_similarity(embedding, tech_embedding)
            if similarity > min_similarity:
                similarities.append((tech_id, similarity))
        
        # Return top 3 matches
        similarities.sort(key=lambda x: x[1], reverse=True)
        return [tech_id for tech_id, _ in similarities[:3]]
    except Exception as e:
        logger.debug(f"ML enrichment unavailable: {e}")
        return []

def compute_text_embedding(text: str) -> np.ndarray:
    """Compute embedding for text using cached model"""
    # This is a simplified version - in production, cache the model
    import boto3
    import json
    import onnxruntime as ort
    from transformers import AutoTokenizer
    
    # Download model if not cached
    model_path = '/tmp/model.onnx'
    if not os.path.exists(model_path):
        s3 = boto3.client('s3')
        s3.download_file(
            'panorama-ml-models-538269499906',
            'onnx/model_int8.onnx',
            model_path
        )
    
    # Load tokenizer
    tokenizer = AutoTokenizer.from_pretrained(
        'sentence-transformers/all-MiniLM-L6-v2',
        cache_dir='/tmp'
    )
    
    # Tokenize and run inference
    session = ort.InferenceSession(model_path)
    inputs = tokenizer(text, padding=True, truncation=True, max_length=128, return_tensors='np')
    outputs = session.run(None, {
        'input_ids': inputs['input_ids'],
        'attention_mask': inputs['attention_mask']
    })
    
    # Mean pooling
    embeddings = outputs[0][0]
    mask = inputs['attention_mask'][0]
    mask_expanded = np.expand_dims(mask, -1)
    sum_embeddings = np.sum(embeddings * mask_expanded, axis=0)
    sum_mask = np.clip(mask_expanded.sum(axis=0), a_min=1e-9, a_max=None)
    return sum_embeddings / sum_mask

def load_technique_embeddings() -> Dict[str, np.ndarray]:
    """Load pre-computed technique embeddings"""
    import boto3
    import json
    
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
    """Compute cosine similarity between two vectors"""
    a_norm = a / np.linalg.norm(a)
    b_norm = b / np.linalg.norm(b)
    return float(np.dot(a_norm, b_norm))

def enrich_rule(rule: DetectionRule, valid_techniques: Dict[str, MitreTechnique], session) -> int:
    """Enrich a single rule with MITRE techniques"""
    found_techniques = set()
    
    # Extract explicit techniques
    found_techniques.update(extract_explicit_techniques(rule))
    
    # Use ML only if we found few explicit techniques
    if len(found_techniques) < 2 and os.environ.get('USE_ML', 'true').lower() == 'true':
        # Build concise text for ML
        text_parts = [rule.name]
        if rule.description:
            text_parts.append(rule.description[:200])
        if rule.tags:
            text_parts.extend([t for t in rule.tags if 'attack' in t.lower()])
        
        rule_text = ' '.join(text_parts)
        ml_techniques = find_similar_techniques(rule_text)
        found_techniques.update(ml_techniques)
    
    # Create mappings
    mappings_created = 0
    for technique_id in found_techniques:
        if technique_id in valid_techniques:
            technique = valid_techniques[technique_id]
            
            # Check if mapping exists
            existing = session.query(RuleMitreMapping).filter_by(
                rule_id=rule.id,
                technique_id=technique.id
            ).first()
            
            if not existing:
                # Create new mapping (no confidence or source exposed)
                mapping = RuleMitreMapping(
                    rule_id=rule.id,
                    technique_id=technique.id,
                    mapping_confidence=1.0,  # Internal use only
                    mapping_source='enricher'  # Internal use only
                )
                session.add(mapping)
                mappings_created += 1
    
    return mappings_created

def lambda_handler(event, context):
    """Lambda handler for MITRE enrichment"""
    
    try:
        rule_ids = event.get('rule_ids')
        batch_size = 250
        total_processed = 0
        total_mappings = 0
        
        with db_session() as session:
            # Load valid techniques once
            techniques = session.query(MitreTechnique).filter(
                MitreTechnique.is_deprecated == False
            ).all()
            valid_techniques = {t.technique_id: t for t in techniques}
            
            logger.info(f"Loaded {len(valid_techniques)} valid MITRE techniques")
            
            # Query rules
            query = session.query(DetectionRule)
            if rule_ids:
                query = query.filter(DetectionRule.id.in_(rule_ids))
            
            rules = query.all()
            logger.info(f"Processing {len(rules)} rules")
            
            # Process in batches
            for i in range(0, len(rules), batch_size):
                batch = rules[i:i + batch_size]
                
                for rule in batch:
                    try:
                        mappings = enrich_rule(rule, valid_techniques, session)
                        total_mappings += mappings
                        total_processed += 1
                    except Exception as e:
                        logger.error(f"Failed to process rule {rule.id}: {e}")
                
                session.commit()
                logger.info(f"Processed batch {i//batch_size + 1}/{(len(rules)-1)//batch_size + 1}")
        
        return {
            'statusCode': 200,
            'processed_rules': total_processed,
            'mappings_created': total_mappings,
            'message': 'MITRE enrichment completed successfully'
        }
        
    except Exception as e:
        logger.error(f"MITRE enrichment failed: {e}", exc_info=True)
        return {
            'statusCode': 500,
            'error': str(e),
            'message': 'MITRE enrichment failed'
        }