# lambda-functions/pano-mitre-orchestrator/lambda_function.py
"""
Orchestrator: Splits work into chunks for parallel processing
"""
import json
import math
from panorama_datamodel import db_session
from panorama_datamodel.models import DetectionRule

def lambda_handler(event, context):
    chunk_size = event.get('chunk_size', 100)
    
    with db_session() as session:
        # Only unmapped rules
        mapped_rule_ids = session.query(RuleMitreMapping.rule_id).distinct().subquery()
        unmapped_rules = session.query(DetectionRule.id).filter(
            ~DetectionRule.id.in_(mapped_rule_ids)
        ).all()
        rule_ids = [r[0] for r in unmapped_rules]
    
    logger.info(f"Found {len(rule_ids)} unmapped rules")
    
    chunks = []
    for i in range(0, len(rule_ids), chunk_size):
        chunks.append({
            'chunk_id': i // chunk_size,
            'rule_ids': rule_ids[i:i + chunk_size]
        })
    
    return {'chunks': chunks, 'total': len(rule_ids)}