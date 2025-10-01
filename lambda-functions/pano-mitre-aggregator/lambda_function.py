# lambda-functions/pano-mitre-aggregator/lambda_function.py
"""
Aggregator: Collects results from all workers
"""
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """Aggregate results from all worker executions"""
    
    # Step Functions passes array of worker results
    worker_results = event
    
    total_rules = sum(r.get('rules_processed', 0) for r in worker_results)
    total_mappings = sum(r.get('mappings_created', 0) for r in worker_results)
    failed_chunks = [r['chunk_id'] for r in worker_results if r.get('error')]
    
    logger.info(f"Aggregated results: {total_rules} rules, {total_mappings} mappings")
    
    if failed_chunks:
        logger.warning(f"Failed chunks: {failed_chunks}")
    
    return {
        'statusCode': 200,
        'total_rules_processed': total_rules,
        'total_mappings_created': total_mappings,
        'failed_chunks': failed_chunks,
        'success': len(failed_chunks) == 0
    }