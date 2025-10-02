# lambda-functions/pano-compute-embeddings/lambda_function.py
import json
import boto3
import logging
from typing import List
import numpy as np
import onnxruntime as ort
from transformers import AutoTokenizer
from sqlalchemy.orm import joinedload

from panorama_datamodel import db_session
from panorama_datamodel.models import MitreTechnique, MitreTactic

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client('s3')

MODEL_BUCKET = 'panorama-ml-models-538269499906'
MAX_LENGTH = 512  # Increased from 128 to capture more context


def build_technique_text(technique: MitreTechnique, tactic: MitreTactic = None) -> str:
    """Build comprehensive text representation using all STIX metadata"""
    parts = []
    
    # Technique identity
    parts.append(f"{technique.technique_id} {technique.name}")
    
    # Full description (don't truncate - model will handle)
    if technique.description:
        parts.append(technique.description)
    
    # Detection description is CRITICAL - explains what logs/patterns indicate this technique
    # This is what makes detection rules correlate to techniques
    if technique.detection_description:
        parts.append(f"Detection: {technique.detection_description}")
    
    # Tactic context (e.g., "Credential Access", "Command and Control")
    if tactic:
        parts.append(f"Tactic: {tactic.name}")
    
    # Kill chain phases (e.g., "initial-access", "execution")
    if technique.kill_chain_phases:
        phases = ' '.join(technique.kill_chain_phases)
        parts.append(f"Phases: {phases}")
    
    # Platforms (e.g., "Windows", "Linux", "Network")
    if technique.platforms:
        platforms = ' '.join(technique.platforms)
        parts.append(f"Platforms: {platforms}")
    
    # Data sources - describes what logs/telemetry would show this technique
    # e.g., "Process: Process Creation", "Network Traffic: Network Connection Creation"
    if technique.data_sources:
        # Normalize data sources to natural language
        sources = []
        for ds in technique.data_sources:
            # Convert "Process: Process Creation" to "process creation"
            normalized = ds.replace(':', '').replace('_', ' ').lower()
            sources.append(normalized)
        parts.append(f"Data sources: {' '.join(sources)}")
    
    # Parent technique context for subtechniques
    if technique.parent_technique_id:
        parent = technique.parent_technique
        if parent:
            parts.append(f"Parent: {parent.name}")
    
    return ' '.join(parts)


def compute_embedding(text: str, tokenizer, session) -> np.ndarray:
    """Compute sentence embedding with mean pooling"""
    inputs = tokenizer(
        text,
        padding=True,
        truncation=True,
        max_length=MAX_LENGTH,
        return_tensors='np'
    )
    
    outputs = session.run(None, {
        'input_ids': inputs['input_ids'].astype(np.int64),
        'attention_mask': inputs['attention_mask'].astype(np.int64)
    })
    
    # Mean pooling with attention mask
    token_embeddings = outputs[0][0]
    attention_mask = inputs['attention_mask'][0]
    
    # Expand mask dimensions
    mask_expanded = np.expand_dims(attention_mask, -1)
    
    # Sum embeddings for non-padding tokens
    sum_embeddings = np.sum(token_embeddings * mask_expanded, axis=0)
    sum_mask = np.clip(mask_expanded.sum(axis=0), a_min=1e-9, a_max=None)
    
    return sum_embeddings / sum_mask


def lambda_handler(event, context):
    """Generate technique embeddings from STIX data"""
    
    try:
        # Download model
        logger.info(f"Downloading model from s3://{MODEL_BUCKET}/onnx/model_int8.onnx")
        s3.download_file(MODEL_BUCKET, 'onnx/model_int8.onnx', '/tmp/model.onnx')
        
        # Load ONNX session
        logger.info("Loading ONNX model...")
        session = ort.InferenceSession('/tmp/model.onnx')
        
        # Load tokenizer
        logger.info("Loading tokenizer...")
        tokenizer = AutoTokenizer.from_pretrained(
            'sentence-transformers/all-MiniLM-L6-v2',
            cache_dir='/tmp'
        )
        
        # Fetch techniques with tactic relationship
        logger.info("Fetching techniques from database...")
        with db_session() as db:
            techniques = db.query(MitreTechnique).options(
                joinedload(MitreTechnique.tactic),
                joinedload(MitreTechnique.parent_technique)
            ).filter(
                MitreTechnique.is_deprecated == False,
                MitreTechnique.revoked == False
            ).all()
            
            logger.info(f"Processing {len(techniques)} techniques...")
            
            embeddings = {}
            skipped = 0
            
            for i, tech in enumerate(techniques):
                try:
                    # Build comprehensive text
                    text = build_technique_text(tech, tech.tactic)
                    
                    # Log first few for debugging
                    if i < 3:
                        logger.info(f"Sample {tech.technique_id} text ({len(text)} chars): {text[:300]}...")
                    
                    # Compute embedding
                    embedding = compute_embedding(text, tokenizer, session)
                    embeddings[tech.technique_id] = embedding.tolist()
                    
                    if (i + 1) % 100 == 0:
                        logger.info(f"Processed {i + 1}/{len(techniques)} techniques")
                
                except Exception as e:
                    logger.error(f"Failed to process {tech.technique_id}: {e}")
                    skipped += 1
            
            logger.info(f"Successfully generated {len(embeddings)} embeddings, skipped {skipped}")
        
        # Upload to S3
        logger.info("Uploading embeddings to S3...")
        embedding_data = json.dumps(embeddings)
        
        s3.put_object(
            Bucket=MODEL_BUCKET,
            Key='onnx/technique_embeddings.json',
            Body=embedding_data
        )
        
        # Upload metadata
        metadata = {
            'technique_count': len(embeddings),
            'model': 'all-MiniLM-L6-v2',
            'max_length': MAX_LENGTH,
            'embedding_dim': len(next(iter(embeddings.values()))),
            'generated_at': context.get_remaining_time_in_millis(),
            'includes_detection_descriptions': True,
            'includes_data_sources': True
        }
        
        s3.put_object(
            Bucket=MODEL_BUCKET,
            Key='onnx/embeddings_metadata.json',
            Body=json.dumps(metadata, indent=2)
        )
        
        return {
            'statusCode': 200,
            'techniques_processed': len(embeddings),
            'techniques_skipped': skipped
        }
    
    except Exception as e:
        logger.error(f"Embedding generation failed: {e}", exc_info=True)
        return {
            'statusCode': 500,
            'error': str(e)
        }