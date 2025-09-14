"""
Sigma Rules Processor - Database import handler
"""
import json
import logging
import os
import boto3
import hashlib
import re
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from decimal import Decimal

import psycopg2
from psycopg2.extras import RealDictCursor, Json

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3_client = boto3.client('s3')
secrets_client = boto3.client('secretsmanager')
lambda_client = boto3.client('lambda')

DB_HOST = os.environ.get('DB_HOST')
DB_PORT = os.environ.get('DB_PORT', '5432')
DB_NAME = os.environ.get('DB_NAME')
DB_USER = os.environ.get('DB_USER')
DB_SECRET_ARN = os.environ.get('DB_SECRET_ARN')


class SigmaRuleProcessor:
    
    SOURCE_NAME = 'Sigma'
    
    SEVERITY_MAP = {
        'informational': 'info',
        'low': 'low',
        'medium': 'medium',
        'high': 'high',
        'critical': 'critical'
    }
    
    STATUS_CONFIDENCE = {
        'stable': Decimal('0.9'),
        'test': Decimal('0.7'),
        'experimental': Decimal('0.5'),
        'deprecated': Decimal('0.3'),
        'unsupported': Decimal('0.2')
    }
    
    def __init__(self):
        self.db_conn = None
        self.source_id = None
        self.stats = {
            'processed': 0,
            'created': 0,
            'updated': 0,
            'skipped': 0,
            'errors': 0,
            'mitre_mappings': 0,
            'cve_references': 0
        }
        self.mitre_queue = []
        self.cve_queue = []
        
    def connect_db(self):
        if self.db_conn and not self.db_conn.closed:
            return self.db_conn
            
        secret_response = secrets_client.get_secret_value(
            SecretId=DB_SECRET_ARN
        )
        secret = json.loads(secret_response['SecretString'])
        password = secret.get('password')
        
        self.db_conn = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            database=DB_NAME,
            user=DB_USER,
            password=password
        )
        return self.db_conn
    
    def get_source_id(self):
        if self.source_id:
            return self.source_id
            
        conn = self.connect_db()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT id FROM rule_sources WHERE name = %s",
                (self.SOURCE_NAME,)
            )
            result = cur.fetchone()
            
            if result:
                self.source_id = result['id']
            else:
                cur.execute(
                    """
                    INSERT INTO rule_sources (
                        name, description, source_type, base_url, 
                        source_metadata, is_active
                    )
                    VALUES (%s, %s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (
                        self.SOURCE_NAME,
                        'Community detection rules from SigmaHQ',
                        'Community',
                        'https://github.com/SigmaHQ/sigma',
                        Json({
                            'repository': 'https://github.com/SigmaHQ/sigma',
                            'type': 'community',
                            'license': 'DRL 1.1',
                            'auto_imported': True
                        }),
                        True
                    )
                )
                self.source_id = cur.fetchone()['id']
                conn.commit()
                logger.info(f"Created source: {self.SOURCE_NAME} (ID: {self.source_id})")
                
        return self.source_id
    
    def process_rules(self, rules_data: Dict[str, Any]) -> Dict[str, Any]:
        source_id = self.get_source_id()
        conn = self.connect_db()
        
        for rule in rules_data['rules']:
            try:
                self._process_rule(rule, source_id, conn)
                self.stats['processed'] += 1
                
                if self.stats['processed'] % 100 == 0:
                    conn.commit()
                    logger.info(f"Processed {self.stats['processed']} rules")
                    
            except Exception as e:
                logger.error(f"Error processing rule {rule.get('rule_id')}: {str(e)}")
                self.stats['errors'] += 1
                conn.rollback()
        
        conn.commit()
        
        # Update source timestamp
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE rule_sources SET last_updated = %s WHERE id = %s",
                (datetime.now(timezone.utc), source_id)
            )
            conn.commit()
        
        # Trigger enrichment if needed
        if self.mitre_queue or self.cve_queue:
            self._trigger_enrichment()
        
        return self.stats
    
    def _process_rule(self, rule: Dict[str, Any], source_id: int, conn):
        # Check for existing rule
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, rule_metadata->>'content_hash' as content_hash
                FROM detection_rules
                WHERE rule_id = %s AND source_id = %s
                """,
                (rule['rule_id'], source_id)
            )
            existing = cur.fetchone()
        
        # Build rule metadata
        metadata = self._build_metadata(rule)
        
        if existing:
            if existing['content_hash'] != rule['content_hash']:
                self._update_rule(existing['id'], rule, metadata, conn)
                self.stats['updated'] += 1
            else:
                self.stats['skipped'] += 1
        else:
            rule_id = self._create_rule(rule, metadata, source_id, conn)
            self.stats['created'] += 1
            
            # Queue for enrichment
            if rule['mitre_techniques']:
                self.mitre_queue.append({
                    'rule_id': rule_id,
                    'techniques': rule['mitre_techniques']
                })
                
            # Check for CVE references
            cves = self._extract_cves(rule)
            if cves:
                self.cve_queue.append({
                    'rule_id': rule_id,
                    'cves': cves
                })
    
    def _build_metadata(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        return {
            'source_org': 'SigmaHQ',
            'source_path': rule['file_path'],
            'original_format': 'sigma',
            'content_hash': rule['content_hash'],
            'status': rule['status'],
            'author': rule['author'],
            'date': rule['date'],
            'modified': rule['modified'],
            'logsource': rule['logsource'],
            'detection': rule['detection'],
            'falsepositives': rule['falsepositives'],
            'references': rule['references'],
            'data_sources': rule['data_sources'],
            'mitre_techniques': rule['mitre_techniques'],
            'license': 'DRL 1.1',
            'validation': {
                'syntax_valid': True,
                'tested': rule['status'] in ['stable', 'test']
            }
        }
    
    def _create_rule(self, rule: Dict[str, Any], metadata: Dict[str, Any], 
                     source_id: int, conn) -> int:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO detection_rules (
                    rule_id, source_id, name, description, rule_content,
                    rule_type, severity, confidence_score, tags, 
                    rule_metadata, is_active
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    rule['rule_id'],
                    source_id,
                    rule['name'],
                    rule['description'],
                    rule['raw_content'],
                    'sigma',
                    self.SEVERITY_MAP.get(rule['severity'], 'medium'),
                    self.STATUS_CONFIDENCE.get(rule['status'], Decimal('0.5')),
                    rule['tags'],
                    Json(metadata),
                    rule['status'] != 'deprecated'
                )
            )
            return cur.fetchone()[0]
    
    def _update_rule(self, rule_id: int, rule: Dict[str, Any], 
                     metadata: Dict[str, Any], conn):
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE detection_rules
                SET name = %s,
                    description = %s,
                    rule_content = %s,
                    severity = %s,
                    confidence_score = %s,
                    tags = %s,
                    rule_metadata = %s,
                    is_active = %s,
                    updated_date = CURRENT_TIMESTAMP
                WHERE id = %s
                """,
                (
                    rule['name'],
                    rule['description'],
                    rule['raw_content'],
                    self.SEVERITY_MAP.get(rule['severity'], 'medium'),
                    self.STATUS_CONFIDENCE.get(rule['status'], Decimal('0.5')),
                    rule['tags'],
                    Json(metadata),
                    rule['status'] != 'deprecated',
                    rule_id
                )
            )
    
    def _extract_cves(self, rule: Dict[str, Any]) -> List[str]:
        cves = []
        cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}')
        
        # Check description and references
        text_to_search = [
            rule.get('description', ''),
            ' '.join(rule.get('references', []))
        ]
        
        for text in text_to_search:
            matches = cve_pattern.findall(text)
            cves.extend(matches)
            
        return list(set(cves))
    
    def _trigger_enrichment(self):
        # Trigger MITRE enrichment
        if self.mitre_queue:
            try:
                payload = {
                    'action': 'enrich_sigma_rules',
                    'mappings': self.mitre_queue[:100]  # Process in batches
                }
                
                lambda_client.invoke(
                    FunctionName='mitre-enricher',
                    InvocationType='Event',
                    Payload=json.dumps(payload)
                )
                
                self.stats['mitre_mappings'] = len(self.mitre_queue)
                logger.info(f"Queued {len(self.mitre_queue)} rules for MITRE enrichment")
            except Exception as e:
                logger.error(f"Failed to trigger MITRE enrichment: {str(e)}")
        
        # Trigger CVE enrichment
        if self.cve_queue:
            try:
                payload = {
                    'action': 'enrich_cve_references',
                    'mappings': self.cve_queue[:100]
                }
                
                lambda_client.invoke(
                    FunctionName='cve-enricher',
                    InvocationType='Event',
                    Payload=json.dumps(payload)
                )
                
                self.stats['cve_references'] = len(self.cve_queue)
                logger.info(f"Queued {len(self.cve_queue)} rules for CVE enrichment")
            except Exception as e:
                logger.error(f"Failed to trigger CVE enrichment: {str(e)}")


def lambda_handler(event, context):
    start_time = datetime.now(timezone.utc)
    
    try:
        # Extract S3 details from event
        if 'Records' in event:
            record = event['Records'][0]
            bucket = record['s3']['bucket']['name']
            key = record['s3']['object']['key']
        else:
            bucket = event.get('bucket', 'panorama-rulesets-538269499906')
            key = event.get('key')
        
        if not key:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'No S3 key provided'})
            }
        
        logger.info(f"Processing Sigma rules from s3://{bucket}/{key}")
        
        # Download rules from S3
        response = s3_client.get_object(Bucket=bucket, Key=key)
        rules_data = json.loads(response['Body'].read())
        
        logger.info(f"Loaded {rules_data['total_rules']} rules from {rules_data['source']}")
        
        # Process rules
        processor = SigmaRuleProcessor()
        stats = processor.process_rules(rules_data)
        
        # Clean up
        if processor.db_conn:
            processor.db_conn.close()
        
        duration = (datetime.now(timezone.utc) - start_time).total_seconds()
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Sigma rules processed successfully',
                'source': rules_data['source'],
                'statistics': stats,
                'duration_seconds': duration,
                'timestamp': start_time.isoformat()
            })
        }
        
    except Exception as e:
        logger.error(f"Processing failed: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': 'Processing failed',
                'message': str(e),
                'timestamp': start_time.isoformat()
            })
        }