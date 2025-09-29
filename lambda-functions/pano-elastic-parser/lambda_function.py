"""
pano-elastic-parser/lambda_function.py
Parses Elastic detection rules (TOML format) for universal processor
"""
import json
import logging
import os
import boto3
import hashlib
import toml
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3_client = boto3.client('s3')
eventbridge_client = boto3.client('events')

STAGING_BUCKET = os.environ.get('STAGING_BUCKET', 'panorama-rulesets')
EVENT_BUS = os.environ.get('EVENT_BUS', 'panorama-rules-processing')

class ElasticRuleParser:
    """Parse Elastic detection rules from TOML format"""
    
    # Severity mapping
    RISK_SCORE_TO_SEVERITY = {
        (0, 20): 'low',
        (21, 40): 'low',
        (41, 60): 'medium',
        (61, 80): 'high',
        (81, 100): 'critical'
    }
    
    def __init__(self):
        self.stats = {
            'parsed': 0,
            'failed': 0,
            'total': 0,
            'rule_types': {}
        }
    
    def parse_rules(self, rules_data: List[Dict]) -> List[Dict[str, Any]]:
        """Parse Elastic rules from downloaded data"""
        
        parsed_rules = []
        
        for rule_entry in rules_data:
            try:
                # Parse TOML content
                rule_content = toml.loads(rule_entry['content'])
                
                # Normalize to common format
                normalized = self._normalize_rule(rule_content, rule_entry['path'])
                if normalized:
                    parsed_rules.append(normalized)
                    self.stats['parsed'] += 1
                    
                    # Track rule type
                    rule_type = normalized.get('metadata', {}).get('rule_type', 'unknown')
                    self.stats['rule_types'][rule_type] = self.stats['rule_types'].get(rule_type, 0) + 1
                else:
                    self.stats['failed'] += 1
                    
            except Exception as e:
                logger.debug(f"Failed to parse {rule_entry['path']}: {e}")
                self.stats['failed'] += 1
            
            self.stats['total'] += 1
        
        return parsed_rules
    
    def _normalize_rule(self, rule: Dict, file_path: str) -> Optional[Dict[str, Any]]:
        """Normalize Elastic rule to common format"""
        
        # Extract rule metadata
        metadata = rule.get('metadata', {})
        rule_info = rule.get('rule', {})
        
        # Skip if missing required fields
        if not rule_info.get('name') or not rule_info.get('query'):
            return None
        
        # Extract fields
        rule_id = rule_info.get('rule_id', hashlib.md5(rule_info['name'].encode()).hexdigest())
        name = rule_info['name']
        description = rule_info.get('description', '')
        
        # Determine severity
        risk_score = rule_info.get('risk_score', 50)
        severity = self._map_severity(risk_score)
        
        # Extract MITRE techniques
        mitre_techniques = self._extract_mitre_techniques(rule_info)
        
        # Build tags
        tags = self._build_tags(rule_info)
        
        # Extract references
        references = rule_info.get('references', [])
        
        # Extract false positives
        false_positives = rule_info.get('false_positives', [])
        
        return {
            'original_id': f"elastic:{rule_id}",
            'title': name,
            'description': description,
            'severity': severity,
            'confidence_score': 0.9,  # Elastic rules are well-maintained
            'tags': tags,
            'mitre_techniques': mitre_techniques,
            'false_positives': false_positives,
            'references': references,
            'cve_references': [],  # Elastic rules rarely include CVEs directly
            'source': 'elastic',
            'source_version': metadata.get('updated_date', ''),
            'status': 'active' if rule_info.get('enabled', True) else 'inactive',
            
            'detection_logic': {
                'format': 'elastic',
                'content': rule_info.get('query', ''),
                'language': rule_info.get('language', 'kuery'),
                'parsed': {
                    'query': rule_info.get('query'),
                    'language': rule_info.get('language', 'kuery'),
                    'index': rule_info.get('index', []),
                    'filters': rule_info.get('filters', []),
                    'type': rule_info.get('type', 'query'),
                    'threshold': rule_info.get('threshold'),
                    'timeline_id': rule_info.get('timeline_id'),
                    'timeline_title': rule_info.get('timeline_title')
                }
            },
            
            'metadata': {
                'rule_id': rule_id,
                'rule_type': rule_info.get('type', 'query'),
                'risk_score': risk_score,
                'severity_mapping': rule_info.get('severity_mapping', []),
                'author': rule_info.get('author', []),
                'license': rule_info.get('license', ''),
                'file_path': file_path,
                'content_hash': hashlib.sha256(json.dumps(rule_info, sort_keys=True).encode()).hexdigest()[:16],
                'platforms': self._extract_platforms(rule_info),
                'data_sources': self._extract_data_sources(rule_info),
                'created': metadata.get('creation_date'),
                'updated': metadata.get('updated_date'),
                'maturity': metadata.get('maturity', 'production'),
                'min_stack_version': metadata.get('min_stack_version')
            }
        }
    
    def _map_severity(self, risk_score: int) -> str:
        """Map risk score to severity"""
        
        for (low, high), severity in self.RISK_SCORE_TO_SEVERITY.items():
            if low <= risk_score <= high:
                return severity
        return 'medium'
    
    def _extract_mitre_techniques(self, rule_info: Dict) -> List[str]:
        """Extract raw MITRE threat data for enricher processing"""
        
        techniques = []
        threat_info = rule_info.get('threat', [])
        
        # Pass through raw threat data for enricher to process
        for threat in threat_info:
            if threat.get('framework') == 'MITRE ATT&CK':
                # Preserve original threat structure as JSON string
                techniques.append(f"threat:{json.dumps(threat)}")
        
        return techniques
    
    def _build_tags(self, rule_info: Dict) -> List[str]:
        """Build tags from rule info"""
        
        tags = []
        
        # Add rule type
        rule_type = rule_info.get('type', 'query')
        tags.append(f"type:{rule_type}")
        
        # Add data source tags
        for index in rule_info.get('index', []):
            if '*' not in index:
                tags.append(f"index:{index}")
        
        # Add threat tags
        for threat in rule_info.get('threat', []):
            tactic = threat.get('tactic', {}).get('name')
            if tactic:
                tags.append(f"tactic:{tactic.lower().replace(' ', '_')}")
        
        # Add custom tags
        tags.extend(rule_info.get('tags', []))
        
        # Add platform tag
        tags.append("siem:elastic")
        
        return list(set(tags))
    
    def _extract_platforms(self, rule_info: Dict) -> List[str]:
        """Extract target platforms from rule"""
        
        platforms = []
        query = rule_info.get('query', '').lower()
        indices = rule_info.get('index', [])
        
        # Determine platforms from indices and query
        if any('windows' in idx.lower() for idx in indices) or 'event.code' in query:
            platforms.append('windows')
        
        if any('linux' in idx.lower() or 'auditbeat' in idx.lower() for idx in indices):
            platforms.append('linux')
        
        if any('macos' in idx.lower() for idx in indices):
            platforms.append('macos')
        
        if any('firewall' in idx.lower() or 'packetbeat' in idx.lower() for idx in indices):
            platforms.append('network')
        
        if any('cloud' in idx.lower() or 'aws' in idx.lower() or 'gcp' in idx.lower() or 'azure' in idx.lower() for idx in indices):
            platforms.append('cloud')
        
        # Default to generic if no specific platform identified
        if not platforms:
            platforms.append('generic')
        
        return platforms
    
    def _extract_data_sources(self, rule_info: Dict) -> List[str]:
        """Extract data sources from rule"""
        
        data_sources = []
        indices = rule_info.get('index', [])
        
        for index in indices:
            if 'winlogbeat' in index:
                data_sources.append('windows:eventlog')
            elif 'auditbeat' in index:
                data_sources.append('linux:auditd')
            elif 'filebeat' in index:
                data_sources.append('logs:application')
            elif 'packetbeat' in index:
                data_sources.append('network:traffic')
            elif 'aws' in index:
                data_sources.append('cloud:aws')
            elif 'gcp' in index:
                data_sources.append('cloud:gcp')
            elif 'azure' in index:
                data_sources.append('cloud:azure')
            elif 'endpoint' in index:
                data_sources.append('endpoint:telemetry')
        
        return list(set(data_sources)) or ['logs:generic']


def lambda_handler(event, context):
    """Lambda handler for Elastic rule parsing"""
    
    try:
        # Parse EventBridge event
        detail = json.loads(event.get('detail', '{}')) if isinstance(event.get('detail'), str) else event.get('detail', {})
        
        s3_bucket = detail.get('s3_bucket', STAGING_BUCKET)
        s3_key = detail.get('s3_key')
        ruleset_id = detail.get('ruleset_id')
        
        if not s3_key:
            raise ValueError("Missing s3_key in event detail")
        
        logger.info(f"Processing Elastic ruleset {ruleset_id} from s3://{s3_bucket}/{s3_key}")
        
        # Download rules data from S3
        response = s3_client.get_object(Bucket=s3_bucket, Key=s3_key)
        rules_data = json.loads(response['Body'].read())
        
        # Parse rules
        parser = ElasticRuleParser()
        parsed_rules = parser.parse_rules(rules_data.get('rules', []))
        
        # Upload parsed rules to S3
        parsed_key = s3_key.replace('/rules.json', '/parsed.json')
        
        parsed_data = {
            'source': 'elastic',
            'ruleset_id': ruleset_id,
            'parsed_at': datetime.now(timezone.utc).isoformat(),
            'statistics': parser.stats,
            'rules': parsed_rules
        }
        
        s3_client.put_object(
            Bucket=s3_bucket,
            Key=parsed_key,
            Body=json.dumps(parsed_data),
            ContentType='application/json'
        )
        
        # Publish event for universal processor
        eventbridge_client.put_events(
            Entries=[{
                'Source': 'rules.parser.elastic',
                'DetailType': 'com.security.rules.parsed',
                'Detail': json.dumps({
                    'ruleset_id': ruleset_id,
                    'source': 'elastic',
                    's3_bucket': s3_bucket,
                    's3_key': parsed_key,
                    'rule_count': len(parsed_rules),
                    'statistics': parser.stats,
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }),
                'EventBusName': EVENT_BUS
            }]
        )
        
        logger.info(f"Successfully parsed {len(parsed_rules)} Elastic rules")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Elastic rules parsed successfully',
                'ruleset_id': ruleset_id,
                'rule_count': len(parsed_rules),
                'statistics': parser.stats
            })
        }
        
    except Exception as e:
        logger.error(f"Parsing failed: {e}", exc_info=True)
        
        # Publish failure event
        eventbridge_client.put_events(
            Entries=[{
                'Source': 'rules.parser.elastic',
                'DetailType': 'com.security.rules.parse.failed',
                'Detail': json.dumps({
                    'ruleset_id': detail.get('ruleset_id', 'unknown'),
                    'source': 'elastic',
                    'error': str(e),
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }),
                'EventBusName': EVENT_BUS
            }]
        )
        
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': 'Parsing failed',
                'message': str(e)
            })
        }