"""
Elastic Detection Rules Processor Lambda
Processes staged Elastic rules and loads them into the database
"""
import json
import logging
import os
import boto3
import psycopg2
from psycopg2.extras import RealDictCursor, execute_batch
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
import hashlib

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

class ElasticRuleProcessor:
    """Process Elastic detection rules into database"""
    
    def __init__(self):
        self.db_conn = None
        self.source_id = None
        self.stats = {
            'created': 0,
            'updated': 0,
            'skipped': 0,
            'errors': 0
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
    
    def ensure_source(self) -> int:
        """Ensure Elastic source exists"""
        if self.source_id:
            return self.source_id
            
        conn = self.connect_db()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                INSERT INTO rule_sources (name, description, source_type)
                VALUES (%s, %s, %s)
                ON CONFLICT (name) DO UPDATE
                SET last_updated = CURRENT_TIMESTAMP
                RETURNING id
                """,
                (
                    'Elastic',
                    'Elastic Security detection rules from elastic/detection-rules',
                    'elastic'
                )
            )
            self.source_id = cur.fetchone()['id']
            conn.commit()
            return self.source_id
    
    def process_manifest(self, bucket: str, manifest_key: str):
        """Process manifest and all rule batches"""
        # Get manifest
        response = s3_client.get_object(Bucket=bucket, Key=manifest_key)
        manifest = json.loads(response['Body'].read())
        
        logger.info(f"Processing Elastic rules version: {manifest['version']}")
        
        conn = self.connect_db()
        source_id = self.ensure_source()
        
        # Process each batch
        for batch_key in manifest['batch_keys']:
            self._process_batch(bucket, batch_key, source_id, conn)
            conn.commit()
        
        # Process MITRE mappings
        if self.mitre_queue:
            self._process_mitre_mappings(conn)
            
        # Trigger enrichment for CVEs if needed
        if self.cve_queue:
            self._trigger_enrichment()
        
        conn.close()
        return self.stats
    
    def _process_batch(self, bucket: str, batch_key: str, source_id: int, conn):
        """Process a batch of rules"""
        response = s3_client.get_object(Bucket=bucket, Key=batch_key)
        rules = json.loads(response['Body'].read())
        
        for rule in rules:
            try:
                self._process_rule(rule, source_id, conn)
            except Exception as e:
                logger.error(f"Error processing rule {rule.get('rule_id')}: {e}")
                self.stats['errors'] += 1
    
    def _process_rule(self, rule: Dict[str, Any], source_id: int, conn):
        """Process individual rule"""
        # Check existing
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, hash
                FROM detection_rules
                WHERE rule_id = %s AND source_id = %s
                """,
                (rule['rule_id'], source_id)
            )
            existing = cur.fetchone()
        
        # Build metadata
        metadata = self._build_metadata(rule)
        
        # Map severity
        severity_map = {
            'critical': 'critical',
            'high': 'high',
            'medium': 'medium',
            'low': 'low',
            'informational': 'info',
            'info': 'info'
        }
        severity = severity_map.get(rule.get('severity', 'medium').lower(), 'medium')
        
        # Calculate confidence based on risk score
        risk_score = rule.get('risk_score', 50)
        confidence = min(risk_score / 100.0, 1.0)
        
        # Compute hash for change detection
        rule_hash = hashlib.sha256(
            json.dumps(metadata, sort_keys=True).encode()
        ).hexdigest()
        
        if existing:
            if existing['hash'] != rule_hash:
                self._update_rule(existing['id'], rule, metadata, severity, confidence, rule_hash, conn)
                self.stats['updated'] += 1
            else:
                self.stats['skipped'] += 1
        else:
            rule_id = self._create_rule(
                rule, metadata, source_id, severity, confidence, rule_hash, conn
            )
            self.stats['created'] += 1
            
            # Queue for MITRE mapping
            if rule.get('mitre_techniques'):
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
    
    def _create_rule(self, rule: Dict, metadata: Dict, source_id: int, 
                    severity: str, confidence: float, rule_hash: str, conn) -> int:
        """Create new rule"""
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                INSERT INTO detection_rules (
                    rule_id, source_id, name, description, rule_content,
                    rule_type, severity, confidence_score, tags, 
                    rule_metadata, hash
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    rule['rule_id'],
                    source_id,
                    rule['name'],
                    rule.get('description', ''),
                    rule.get('query', ''),  # Store query as rule content
                    'elastic',  # Rule type
                    severity,
                    confidence,
                    rule.get('tags', []),
                    json.dumps(metadata),
                    rule_hash
                )
            )
            return cur.fetchone()['id']
    
    def _update_rule(self, rule_db_id: int, rule: Dict, metadata: Dict,
                    severity: str, confidence: float, rule_hash: str, conn):
        """Update existing rule"""
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE detection_rules 
                SET name = %s, description = %s, rule_content = %s,
                    severity = %s, confidence_score = %s, tags = %s,
                    rule_metadata = %s, hash = %s, updated_date = CURRENT_TIMESTAMP
                WHERE id = %s
                """,
                (
                    rule['name'],
                    rule.get('description', ''),
                    rule.get('query', ''),
                    severity,
                    confidence,
                    rule.get('tags', []),
                    json.dumps(metadata),
                    rule_hash,
                    rule_db_id
                )
            )
    
    def _build_metadata(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        """Build comprehensive metadata"""
        return {
            'source_org': 'Elastic',
            'original_format': 'elastic',
            'content_hash': rule['content_hash'],
            'version': rule.get('version'),
            'category': rule.get('category'),
            'rule_type': rule.get('type', 'query'),
            'language': rule.get('language', 'kuery'),
            'risk_score': rule.get('risk_score'),
            'author': rule.get('author', []),
            'license': rule.get('license', 'Elastic License v2'),
            'maturity': rule.get('maturity', 'production'),
            'creation_date': rule.get('creation_date'),
            'updated_date': rule.get('updated_date'),
            'min_stack_version': rule.get('min_stack_version'),
            'enabled': rule.get('enabled', True),
            'interval': rule.get('interval'),
            'from': rule.get('from'),
            'index_patterns': rule.get('index', []),
            'data_sources': rule.get('data_sources', []),
            'platforms': rule.get('platforms', []),
            'false_positives': rule.get('false_positives', []),
            'references': rule.get('references', []),
            'threat': rule.get('threat', []),
            'threshold': rule.get('threshold', {}),
            'timestamp_override': rule.get('timestamp_override'),
            'mitre_techniques': rule.get('mitre_techniques', []),
            'file_path': rule.get('file_path')
        }
    
    def _extract_cves(self, rule: Dict[str, Any]) -> List[str]:
        """Extract CVE references from rule"""
        import re
        cve_pattern = re.compile(r'CVE-\d{4}-\d+')
        cves = set()
        
        # Check description
        if rule.get('description'):
            cves.update(cve_pattern.findall(rule['description']))
        
        # Check references
        for ref in rule.get('references', []):
            cves.update(cve_pattern.findall(ref))
        
        return list(cves)
    
    def _process_mitre_mappings(self, conn):
        """Process MITRE technique mappings"""
        if not self.mitre_queue:
            return
            
        with conn.cursor() as cur:
            # Get technique IDs
            technique_map = {}
            techniques = set()
            for item in self.mitre_queue:
                techniques.update(item['techniques'])
            
            if techniques:
                cur.execute(
                    """
                    SELECT id, technique_id 
                    FROM mitre_techniques 
                    WHERE technique_id = ANY(%s)
                    """,
                    (list(techniques),)
                )
                technique_map = {row[1]: row[0] for row in cur.fetchall()}
            
            # Insert mappings
            mappings = []
            for item in self.mitre_queue:
                for technique in item['techniques']:
                    if technique in technique_map:
                        mappings.append((
                            item['rule_id'],
                            technique_map[technique],
                            0.8,  # Default confidence for Elastic mappings
                            'elastic'
                        ))
            
            if mappings:
                execute_batch(
                    cur,
                    """
                    INSERT INTO rule_mitre_mappings 
                    (rule_id, technique_id, mapping_confidence, mapping_source)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (rule_id, technique_id) DO UPDATE
                    SET mapping_confidence = EXCLUDED.mapping_confidence,
                        mapping_source = EXCLUDED.mapping_source
                    """,
                    mappings
                )
                logger.info(f"Created {len(mappings)} MITRE mappings")
            
            conn.commit()
    
    def _trigger_enrichment(self):
        # Trigger MITRE enrichment
        if self.mitre_queue:
            try:
                payload = {
                    'action': 'enrich_sigma_rules',
                    'mappings': self.mitre_queue[:100]  # Process in batches
                }
                
                lambda_client.invoke(
                    FunctionName='pano-mitre-enricher',
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
                    FunctionName='pano-cve-enricher',
                    InvocationType='Event',
                    Payload=json.dumps(payload)
                )
                
                self.stats['cve_references'] = len(self.cve_queue)
                logger.info(f"Queued {len(self.cve_queue)} rules for CVE enrichment")
            except Exception as e:
                logger.error(f"Failed to trigger CVE enrichment: {str(e)}")


def lambda_handler(event, context):
    """Main Lambda handler"""
    
    try:
        # Get parameters
        manifest_key = event['manifest_key']
        bucket = event.get('bucket', os.environ.get('STAGING_BUCKET'))
        
        logger.info(f"Processing manifest: {manifest_key}")
        
        processor = ElasticRuleProcessor()
        stats = processor.process_manifest(bucket, manifest_key)
        
        logger.info(f"Processing complete: {stats}")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Successfully processed Elastic rules',
                'stats': stats
            })
        }
        
    except Exception as e:
        logger.error(f"Processing failed: {e}", exc_info=True)
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e)
            })
        }