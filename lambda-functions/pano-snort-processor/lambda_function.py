"""
Snort Rules Processor
Managed by Terraform
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


class SnortRuleProcessor:
    
    SOURCE_NAME = 'Snort'
    
    SEVERITY_MAP = {
        'critical': 'critical',
        'high': 'high',
        'medium': 'medium',
        'low': 'low',
        'info': 'info'
    }
    
    # Confidence based on rule priority
    PRIORITY_CONFIDENCE = {
        1: Decimal('0.9'),
        2: Decimal('0.8'),
        3: Decimal('0.7'),
        4: Decimal('0.6')
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
            'cve_references': 0,
            'duplicate_sids': 0
        }
        self.cve_queue = []
        self.processed_sids = set()
        
    def connect_db(self):
        """Establish database connection"""
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
        """Get or create the Snort source"""
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
                        'Snort community detection rules',
                        'Community',
                        'https://www.snort.org/downloads/community',
                        Json({
                            'repository': 'https://www.snort.org',
                            'type': 'community',
                            'license': 'GPL v2',
                            'auto_imported': True,
                            'rule_format': 'snort'
                        }),
                        True
                    )
                )
                self.source_id = cur.fetchone()['id']
                conn.commit()
                logger.info(f"Created source: {self.SOURCE_NAME} (ID: {self.source_id})")
                
        return self.source_id
    
    def process_rules(self, rules_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process all rules and insert into database"""
        source_id = self.get_source_id()
        conn = self.connect_db()
        
        for rule in rules_data['rules']:
            try:
                # Check for duplicate SIDs
                sid = rule.get('sid')
                if sid in self.processed_sids:
                    self.stats['duplicate_sids'] += 1
                    logger.debug(f"Skipping duplicate SID: {sid}")
                    continue
                    
                self._process_rule(rule, source_id, conn)
                self.processed_sids.add(sid)
                self.stats['processed'] += 1
                
                # Commit in batches
                if self.stats['processed'] % 100 == 0:
                    conn.commit()
                    logger.info(f"Processed {self.stats['processed']} rules")
                    
            except Exception as e:
                logger.error(f"Error processing rule {rule.get('rule_id')}: {str(e)}")
                self.stats['errors'] += 1
                conn.rollback()
        
        conn.commit()
        
        # Update source timestamp
        self._update_source_timestamp(source_id, conn)
        
        # Trigger CVE enrichment if needed
        if self.cve_queue:
            self._trigger_cve_enrichment()
        
        return self.stats
    
    def _process_rule(self, rule: Dict[str, Any], source_id: int, conn):
        """Process individual rule"""
        
        # Determine confidence score
        priority = rule.get('metadata', {}).get('priority', 3)
        confidence_score = self.PRIORITY_CONFIDENCE.get(priority, Decimal('0.7'))
        
        # Prepare rule data
        rule_data = {
            'rule_id': rule['rule_id'],
            'source_id': source_id,
            'name': rule['name'],
            'description': rule.get('description', rule['name']),
            'rule_content': rule['rule_content'],
            'rule_type': 'snort',
            'severity': self.SEVERITY_MAP.get(rule.get('severity', 'medium'), 'medium'),
            'confidence_score': confidence_score,
            'tags': rule.get('tags', []),
            'rule_metadata': Json(rule.get('metadata', {})),
            'hash': rule['hash']
        }
        
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Check if rule exists
            cur.execute(
                """
                SELECT id, hash, updated_date 
                FROM detection_rules 
                WHERE rule_id = %s AND source_id = %s
                """,
                (rule_data['rule_id'], source_id)
            )
            existing_rule = cur.fetchone()
            
            if existing_rule:
                # Update if hash changed
                if existing_rule['hash'] != rule_data['hash']:
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
                            hash = %s,
                            updated_date = CURRENT_TIMESTAMP
                        WHERE id = %s
                        """,
                        (
                            rule_data['name'],
                            rule_data['description'],
                            rule_data['rule_content'],
                            rule_data['severity'],
                            rule_data['confidence_score'],
                            rule_data['tags'],
                            rule_data['rule_metadata'],
                            rule_data['hash'],
                            existing_rule['id']
                        )
                    )
                    self.stats['updated'] += 1
                    rule_id = existing_rule['id']
                else:
                    self.stats['skipped'] += 1
                    rule_id = existing_rule['id']
            else:
                # Insert new rule
                cur.execute(
                    """
                    INSERT INTO detection_rules (
                        rule_id, source_id, name, description,
                        rule_content, rule_type, severity,
                        confidence_score, tags, rule_metadata, hash
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (
                        rule_data['rule_id'],
                        rule_data['source_id'],
                        rule_data['name'],
                        rule_data['description'],
                        rule_data['rule_content'],
                        rule_data['rule_type'],
                        rule_data['severity'],
                        rule_data['confidence_score'],
                        rule_data['tags'],
                        rule_data['rule_metadata'],
                        rule_data['hash']
                    )
                )
                rule_id = cur.fetchone()['id']
                self.stats['created'] += 1
            
            # Process CVE references
            cve_refs = rule.get('cve_references', [])
            if cve_refs:
                self._process_cve_references(rule_id, cve_refs, cur)
    
    def _process_cve_references(self, rule_id: int, cve_refs: List[str], cursor):
        """Process CVE references for a rule"""
        for cve_id in cve_refs:
            # Normalize CVE ID format
            cve_id = cve_id.upper()
            if not cve_id.startswith('CVE-'):
                cve_id = f'CVE-{cve_id}'
            
            # Queue for enrichment
            self.cve_queue.append({
                'rule_id': rule_id,
                'cve_id': cve_id,
                'source': self.SOURCE_NAME
            })
            self.stats['cve_references'] += 1
    
    def _update_source_timestamp(self, source_id: int, conn):
        """Update the last_updated timestamp for the source"""
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE rule_sources
                SET last_updated = CURRENT_TIMESTAMP,
                    source_metadata = source_metadata || %s
                WHERE id = %s
                """,
                (
                    Json({'last_import_stats': self.stats}),
                    source_id
                )
            )
        conn.commit()
        logger.info(f"Updated source timestamp for {self.SOURCE_NAME}")
    
    def _trigger_cve_enrichment(self):
        """Trigger CVE enrichment Lambda for collected CVE references"""
        if not self.cve_queue:
            return
            
        # Batch CVE references
        unique_cves = {}
        for item in self.cve_queue:
            cve_id = item['cve_id']
            if cve_id not in unique_cves:
                unique_cves[cve_id] = []
            unique_cves[cve_id].append(item['rule_id'])
        
        payload = {
            'source': 'snort-processor',
            'cve_mappings': [
                {
                    'cve_id': cve_id,
                    'rule_ids': rule_ids,
                    'source': self.SOURCE_NAME
                }
                for cve_id, rule_ids in unique_cves.items()
            ]
        }
        
        try:
            response = lambda_client.invoke(
                FunctionName='pano-cve-enricher',
                InvocationType='Event',
                Payload=json.dumps(payload)
            )
            
            self.stats['cve_enrichment_triggered'] = True
            self.stats['unique_cves'] = len(unique_cves)
            logger.info(f"Queued {len(unique_cves)} unique CVEs for enrichment")
        except Exception as e:
            logger.error(f"Failed to trigger CVE enrichment: {str(e)}")


def lambda_handler(event, context):
    """Lambda entry point"""
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
        
        logger.info(f"Processing Snort rules from s3://{bucket}/{key}")
        
        # Download rules from S3
        response = s3_client.get_object(Bucket=bucket, Key=key)
        rules_data = json.loads(response['Body'].read())
        
        logger.info(f"Loaded {rules_data['total_rules']} rules from {rules_data['source']}")
        
        # Process rules
        processor = SnortRuleProcessor()
        stats = processor.process_rules(rules_data)
        
        # Clean up
        if processor.db_conn:
            processor.db_conn.close()
        
        duration = (datetime.now(timezone.utc) - start_time).total_seconds()
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Snort rules processed successfully',
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