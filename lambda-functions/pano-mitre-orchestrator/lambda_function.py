# lambda-functions/pano-mitre-orchestrator/lambda_function.py
"""
Orchestrator: Splits work into chunks for parallel processing
"""
import json
import math
from panorama_datamodel import db_session
from panorama_datamodel.models import DetectionRule

def lambda_handler(event, context):
    """Create work chunks for parallel processing"""
    
    chunk_size = event.get('chunk_size', 100) 
    
    with db_session() as session:
        query = session.query(DetectionRule.id)
        
        if rule_ids := event.get('rule_ids'):
            query = query.filter(DetectionRule.id.in_(rule_ids))
        
        all_rule_ids = [r[0] for r in query.all()]

    chunks = []
    for i in range(0, len(all_rule_ids), chunk_size):
        chunks.append({
            'chunk_id': i // chunk_size,
            'rule_ids': all_rule_ids[i:i + chunk_size],
            'total_chunks': math.ceil(len(all_rule_ids) / chunk_size)
        })
    
    return {
        'statusCode': 200,
        'chunks': chunks,
        'total_rules': len(all_rule_ids),
        'chunk_size': chunk_size
    }