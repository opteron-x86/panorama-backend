"""
pano-universal-processor/lambda_function.py
Universal processor for normalizing and upserting rules to database
"""
import json
import logging
import os
import boto3
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from decimal import Decimal
from contextlib import contextmanager
import yaml

import psycopg2
from psycopg2.extras import RealDictCursor, Json, execute_batch

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3_client = boto3.client('s3')
secrets_client = boto3.client('secretsmanager')
eventbridge_client = boto3.client('events')
lambda_client = boto3.client('lambda')

# Database configuration
DB_HOST = os.environ.get('DB_HOST')
DB_PORT = os.environ.get('DB_PORT', '5432')
DB_NAME = os.environ.get('DB_NAME')
DB_USER = os.environ.get('DB_USER')
DB_SECRET_ARN = os.environ.get('DB_SECRET_ARN')

EVENT_BUS = os.environ.get('EVENT_BUS', 'default')
BATCH_SIZE = int(os.environ.get('BATCH_SIZE', '100'))


class UniversalRuleProcessor:
    """Process rules from any parser into standardized database format"""
    
    SOURCE_MAPPING = {
        'sigma': 'Sigma',
        'snort': 'Snort',
        'yara': 'Yara',
        'elastic': 'Elastic',
        'suricata': 'Suricata',
        'custom': 'Custom'
    }
    
    def __init__(self):
        self.db_conn = None
        self.db_password = None
        self.source_cache = {}
        self.stats = {
            'total': 0,
            'processed': 0,
            'created': 0,
            'updated': 0,
            'errors': 0,
            'batches': 0
        }
        self.enrichment_queues = {
            'mitre': [],
            'cve': [],
            'vulnerability': []
        }
        
    @contextmanager
    def get_db_connection(self):
        """Database connection context manager"""
        conn = self._connect_db()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    
    def _connect_db(self):
        """Create database connection"""
        if not self.db_password:
            secret_response = secrets_client.get_secret_value(SecretId=DB_SECRET_ARN)
            secret = json.loads(secret_response['SecretString'])
            self.db_password = secret.get('password')
        
        return psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            database=DB_NAME,
            user=DB_USER,
            password=self.db_password
        )
    
    def get_or_create_source(self, source_name: str, conn) -> int:
        """Get or create rule source"""
        if source_name in self.source_cache:
            return self.source_cache[source_name]
        
        display_name = self.SOURCE_MAPPING.get(source_name.lower(), source_name)
        
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Try to get existing source
            cur.execute(
                "SELECT id FROM rule_sources WHERE name = %s",
                (display_name,)
            )
            result = cur.fetchone()
            
            if result:
                source_id = result['id']
            else:
                # Create new source
                cur.execute(
                    """
                    INSERT INTO rule_sources (name, description, is_active, created_date)
                    VALUES (%s, %s, %s, %s)
                    RETURNING id
                    """,
                    (
                        display_name,
                        f"{display_name} detection rules",
                        True,
                        datetime.now(timezone.utc)
                    )
                )
                source_id = cur.fetchone()['id']
                logger.info(f"Created new rule source: {display_name} (ID: {source_id})")
            
            self.source_cache[source_name] = source_id
            return source_id
    
    def process_ruleset(self, bucket: str, key: str) -> Dict[str, Any]:
        """Process parsed ruleset from S3"""
        # Download parsed rules
        response = s3_client.get_object(Bucket=bucket, Key=key)
        parsed_data = json.loads(response['Body'].read())
        
        ruleset_id = parsed_data['ruleset_id']
        source = parsed_data['source']
        rules = parsed_data['rules']
        
        logger.info(f"Processing {len(rules)} {source} rules from ruleset {ruleset_id}")
        
        with self.get_db_connection() as conn:
            source_id = self.get_or_create_source(source, conn)
            
            # Process in batches
            for i in range(0, len(rules), BATCH_SIZE):
                batch = rules[i:i + BATCH_SIZE]
                self._process_batch(batch, source_id, ruleset_id, conn)
                self.stats['batches'] += 1
                
                # Intermediate commit for large rulesets
                if i > 0 and i % (BATCH_SIZE * 10) == 0:
                    conn.commit()
                    logger.info(f"Processed {i} rules...")
        
        # Trigger enrichment if needed
        self._trigger_enrichments()
        
        return self.stats
    
    def _process_batch(self, rules: List[Dict], source_id: int, ruleset_id: str, conn):
        """Process batch of rules"""
        # Prepare batch data
        batch_data = []
        existing_ids = self._get_existing_rule_ids(rules, source_id, conn)
        
        for rule in rules:
            try:
                self.stats['total'] += 1
                
                # Generate consistent rule ID
                rule_id = self._generate_rule_id(rule, source_id)
                
                # Normalize rule data
                normalized = self._normalize_rule(rule, rule_id, source_id, ruleset_id)
                
                # Queue for enrichment if needed
                self._queue_enrichments(rule_id, rule)
                
                batch_data.append(normalized)
                self.stats['processed'] += 1
                
            except Exception as e:
                logger.error(f"Failed to process rule {rule.get('original_id')}: {e}")
                self.stats['errors'] += 1
        
        # Perform batch upsert
        if batch_data:
            self._batch_upsert(batch_data, existing_ids, conn)
    
    def _normalize_rule(self, rule: Dict, rule_id: str, source_id: int, ruleset_id: str) -> Dict:
        """Normalize rule to database schema"""
        # Parse dates
        created_date = datetime.now(timezone.utc)
        updated_date = datetime.now(timezone.utc)
        
        if 'metadata' in rule:
            if rule['metadata'].get('original_date'):
                try:
                    created_date = datetime.fromisoformat(rule['metadata']['original_date'])
                except:
                    pass
            if rule['metadata'].get('original_modified'):
                try:
                    updated_date = datetime.fromisoformat(rule['metadata']['original_modified'])
                except:
                    pass
        
        # Convert detection logic to storable format
        detection_content = self._format_detection_logic(rule.get('detection_logic', {}))
        
        # Build complete metadata
        metadata = {
            'source': rule.get('source'),
            'source_version': rule.get('source_version'),
            'status': rule.get('status'),
            'original_id': rule.get('original_id'),
            'ruleset_id': ruleset_id,
            'false_positives': rule.get('false_positives', []),
            'references': rule.get('references', []),
            'cve_references': rule.get('cve_references', []),
            **rule.get('metadata', {})
        }
        
        return {
            'rule_id': rule_id,
            'source_id': source_id,
            'name': rule.get('title', 'Untitled'),
            'description': rule.get('description', ''),
            'rule_content': detection_content,
            'rule_type': rule.get('source', 'unknown'),
            'severity': rule.get('severity', 'medium'),
            'confidence_score': Decimal(str(rule.get('confidence_score', 0.5))),
            'tags': rule.get('tags', []),
            'rule_metadata': metadata,  # Keep as dict, not Json wrapper
            'is_active': rule.get('status') != 'deprecated',
            'created_date': created_date,
            'updated_date': updated_date
        }
    
    def _format_detection_logic(self, detection_logic: Dict) -> str:
        """Format detection logic for storage"""
        if not detection_logic:
            return ''
        
        format_type = detection_logic.get('format', 'unknown')
        content = detection_logic.get('content', {})
        
        if format_type in ['sigma', 'yara', 'snort']:
            # Convert to YAML for readable storage
            return yaml.dump(content, default_flow_style=False)
        elif format_type in ['elastic', 'json']:
            # Keep as JSON
            return json.dumps(content, indent=2)
        else:
            # Default to string representation
            return str(content)
    
    def _generate_rule_id(self, rule: Dict, source_id: int) -> str:
        """Generate deterministic rule ID"""
        original_id = rule.get('original_id', '')
        source = rule.get('source', '')
        
        # Create unique identifier
        unique_string = f"{source}:{source_id}:{original_id}"
        return hashlib.sha256(unique_string.encode()).hexdigest()[:32]
    
    def _get_existing_rule_ids(self, rules: List[Dict], source_id: int, conn) -> Dict[str, Dict]:
        """Get existing rule IDs and metadata for batch"""
        rule_ids = [self._generate_rule_id(rule, source_id) for rule in rules]
        
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT rule_id, id, rule_metadata->>'content_hash' as content_hash,
                       updated_date
                FROM detection_rules
                WHERE rule_id = ANY(%s) AND source_id = %s
                """,
                (rule_ids, source_id)
            )
            
            return {row['rule_id']: row for row in cur.fetchall()}
    
    def _batch_upsert(self, batch_data: List[Dict], existing_ids: Dict, conn):
        """Perform batch upsert of rules"""
        updates = []
        inserts = []
        
        for data in batch_data:
            rule_id = data['rule_id']
            if rule_id in existing_ids:
                # Check if update needed
                existing = existing_ids[rule_id]
                current_hash = data['rule_metadata'].get('content_hash')
                existing_hash = existing.get('content_hash')
                
                if current_hash != existing_hash:
                    updates.append(data)
                    self.stats['updated'] += 1
            else:
                inserts.append(data)
                self.stats['created'] += 1
        
        # Perform batch insert
        if inserts:
            # Wrap metadata with Json for database insertion
            insert_data = []
            for data in inserts:
                insert_record = data.copy()
                insert_record['rule_metadata'] = Json(data['rule_metadata'])
                insert_data.append(insert_record)
            
            with conn.cursor() as cur:
                execute_batch(
                    cur,
                    """
                    INSERT INTO detection_rules (
                        rule_id, source_id, name, description, rule_content,
                        rule_type, severity, confidence_score, tags,
                        rule_metadata, is_active, created_date, updated_date
                    )
                    VALUES (
                        %(rule_id)s, %(source_id)s, %(name)s, %(description)s,
                        %(rule_content)s, %(rule_type)s, %(severity)s,
                        %(confidence_score)s, %(tags)s, %(rule_metadata)s,
                        %(is_active)s, %(created_date)s, %(updated_date)s
                    )
                    """,
                    insert_data,
                    page_size=BATCH_SIZE
                )
        
        # Perform batch update
        if updates:
            # Wrap metadata with Json for database update
            update_data = []
            for data in updates:
                update_record = data.copy()
                update_record['rule_metadata'] = Json(data['rule_metadata'])
                update_data.append(update_record)
                
            with conn.cursor() as cur:
                execute_batch(
                    cur,
                    """
                    UPDATE detection_rules
                    SET name = %(name)s,
                        description = %(description)s,
                        rule_content = %(rule_content)s,
                        severity = %(severity)s,
                        confidence_score = %(confidence_score)s,
                        tags = %(tags)s,
                        rule_metadata = %(rule_metadata)s,
                        is_active = %(is_active)s,
                        updated_date = %(updated_date)s
                    WHERE rule_id = %(rule_id)s AND source_id = %(source_id)s
                    """,
                    update_data,
                    page_size=BATCH_SIZE
                )
    
    def _queue_enrichments(self, rule_id: str, rule: Dict):
        """Queue rule for enrichment processing"""
        # MITRE enrichment
        if rule.get('mitre_techniques'):
            self.enrichment_queues['mitre'].append({
                'rule_id': rule_id,
                'techniques': rule['mitre_techniques']
            })
        
        # CVE enrichment
        if rule.get('cve_references'):
            self.enrichment_queues['cve'].append({
                'rule_id': rule_id,
                'cves': rule['cve_references']
            })
    
    def _trigger_enrichments(self):
        """Trigger enrichment lambdas if needed"""
        # MITRE enrichment
        if self.enrichment_queues['mitre']:
            try:
                payload = {
                    'action': 'enrich_rules',
                    'source': 'universal_processor',
                    'mappings': self.enrichment_queues['mitre'][:500]  # Limit batch size
                }
                
                lambda_client.invoke(
                    FunctionName='pano-mitre-enricher',
                    InvocationType='Event',
                    Payload=json.dumps(payload)
                )
                
                logger.info(f"Queued {len(self.enrichment_queues['mitre'])} rules for MITRE enrichment")
            except Exception as e:
                logger.error(f"Failed to trigger MITRE enrichment: {e}")
        
        # CVE enrichment
        if self.enrichment_queues['cve']:
            try:
                payload = {
                    'action': 'enrich_cve_references',
                    'source': 'universal_processor',
                    'mappings': self.enrichment_queues['cve'][:500]
                }
                
                lambda_client.invoke(
                    FunctionName='pano-cve-enricher',
                    InvocationType='Event',
                    Payload=json.dumps(payload)
                )
                
                logger.info(f"Queued {len(self.enrichment_queues['cve'])} rules for CVE enrichment")
            except Exception as e:
                logger.error(f"Failed to trigger CVE enrichment: {e}")


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda entry point for EventBridge events"""
    start_time = datetime.now(timezone.utc)
    
    try:
        # Parse EventBridge event
        detail = event.get('detail', {})
        if not detail:
            # Fallback for direct invocation
            detail = event
        
        ruleset_id = detail.get('ruleset_id')
        source = detail.get('source')
        s3_bucket = detail.get('s3_bucket')
        s3_key = detail.get('s3_key')
        
        if not s3_key:
            raise ValueError("No S3 key provided")
        
        logger.info(f"Processing {source} ruleset {ruleset_id} from s3://{s3_bucket}/{s3_key}")
        
        # Process ruleset
        processor = UniversalRuleProcessor()
        stats = processor.process_ruleset(s3_bucket, s3_key)
        
        # Publish completion event
        eventbridge_client.put_events(
            Entries=[{
                'Source': 'rules.processor',
                'DetailType': 'com.security.rules.processed',
                'Detail': json.dumps({
                    'ruleset_id': ruleset_id,
                    'source': source,
                    'statistics': stats,
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }),
                'EventBusName': EVENT_BUS
            }]
        )
        
        duration = (datetime.now(timezone.utc) - start_time).total_seconds()
        
        logger.info(f"Successfully processed ruleset in {duration:.2f}s: {stats}")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Rules processed successfully',
                'ruleset_id': ruleset_id,
                'source': source,
                'statistics': stats,
                'duration_seconds': duration
            })
        }
        
    except Exception as e:
        logger.error(f"Processing failed: {e}", exc_info=True)
        
        # Publish failure event
        try:
            eventbridge_client.put_events(
                Entries=[{
                    'Source': 'rules.processor',
                    'DetailType': 'com.security.rules.failed',
                    'Detail': json.dumps({
                        'ruleset_id': detail.get('ruleset_id', 'unknown'),
                        'source': detail.get('source', 'unknown'),
                        'error': str(e),
                        'failure_type': 'process_failed',
                        'timestamp': datetime.now(timezone.utc).isoformat()
                    }),
                    'EventBusName': EVENT_BUS
                }]
            )
        except:
            pass
        
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': 'Processing failed',
                'message': str(e),
                'timestamp': start_time.isoformat()
            })
        }