"""
pano-sigma-parser/lambda_function.py
Parses Sigma rules to intermediate format for universal processor
"""
import json
import logging
import os
import boto3
import hashlib
import re
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
import yaml

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3_client = boto3.client('s3')
eventbridge_client = boto3.client('events')

STAGING_BUCKET = os.environ.get('STAGING_BUCKET', 'panorama-rulesets')
EVENT_BUS = os.environ.get('EVENT_BUS', 'default')


class SigmaParser:
    """Parse Sigma rules to intermediate format"""
    
    SEVERITY_MAP = {
        'informational': 'info',
        'low': 'low',
        'medium': 'medium',
        'high': 'high',
        'critical': 'critical'
    }
    
    STATUS_CONFIDENCE = {
        'stable': 0.9,
        'test': 0.7,
        'experimental': 0.5,
        'deprecated': 0.3,
        'unsupported': 0.2
    }
    
    def __init__(self):
        self.stats = {
            'total': 0,
            'parsed': 0,
            'errors': 0,
            'categories': set()
        }
        
    def parse_ruleset(self, rules_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse entire ruleset to intermediate format"""
        parsed_rules = []
        ruleset_id = self._generate_ruleset_id(rules_data)
        
        for category, rules in rules_data.get('rules', {}).items():
            self.stats['categories'].add(category)
            for rule in rules:
                self.stats['total'] += 1
                try:
                    parsed = self._parse_rule(rule)
                    if parsed:
                        parsed_rules.append(parsed)
                        self.stats['parsed'] += 1
                except Exception as e:
                    logger.error(f"Failed to parse rule {rule.get('rule_id')}: {e}")
                    self.stats['errors'] += 1
        
        return {
            'ruleset_id': ruleset_id,
            'source': 'sigma',
            'parser_version': '1.0',
            'parsed_at': datetime.now(timezone.utc).isoformat(),
            'statistics': {
                'total': self.stats['total'],
                'parsed': self.stats['parsed'],
                'errors': self.stats['errors'],
                'categories': list(self.stats['categories'])
            },
            'rules': parsed_rules
        }
    
    def _parse_rule(self, rule: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse single Sigma rule to intermediate format"""
        if not rule.get('rule_id') or not rule.get('detection'):
            return None
            
        # Extract MITRE techniques
        mitre_techniques = self._extract_mitre_techniques(rule)
        
        # Extract platforms and data sources
        logsource = rule.get('logsource', {})
        platforms = self._extract_platforms(logsource)
        data_sources = self._extract_data_sources(logsource)
        
        # Build intermediate format
        parsed = {
            'original_id': rule['rule_id'],
            'title': rule.get('name', rule.get('title', 'Untitled')),
            'description': rule.get('description', ''),
            'severity': self.SEVERITY_MAP.get(rule.get('severity', 'medium'), 'medium'),
            'confidence_score': self.STATUS_CONFIDENCE.get(rule.get('status', 'experimental'), 0.5),
            'tags': rule.get('tags', []),
            'mitre_techniques': mitre_techniques,
            'false_positives': rule.get('falsepositives', []),
            'references': rule.get('references', []),
            'source': 'sigma',
            'source_version': rule.get('version', '1.0'),
            'status': rule.get('status', 'experimental'),
            
            # Detection logic in structured format
            'detection_logic': {
                'format': 'sigma',
                'content': rule['detection'],
                'logsource': logsource
            },
            
            # Metadata
            'metadata': {
                'original_author': rule.get('author', ''),
                'original_date': rule.get('date', ''),
                'original_modified': rule.get('modified', ''),
                'license': rule.get('license', 'DRL 1.1'),
                'file_path': rule.get('file_path', ''),
                'content_hash': rule.get('content_hash', self._generate_hash(rule)),
                'platforms': platforms,
                'data_sources': data_sources
            }
        }
        
        # Extract CVE references if any
        cves = self._extract_cves(rule)
        if cves:
            parsed['cve_references'] = cves
            
        return parsed
    
    def _extract_mitre_techniques(self, rule: Dict[str, Any]) -> List[str]:
        """Extract MITRE ATT&CK techniques from rule"""
        techniques = []
        
        # Check tags for MITRE patterns
        for tag in rule.get('tags', []):
            if isinstance(tag, str):
                # Pattern: attack.t1234 or attack.T1234.001
                if tag.startswith('attack.t') or tag.startswith('attack.T'):
                    technique = tag.replace('attack.', '').upper()
                    if re.match(r'T\d{4}(\.\d{3})?', technique):
                        techniques.append(technique)
        
        # Check explicit mitre_techniques field
        if 'mitre_techniques' in rule:
            techniques.extend(rule['mitre_techniques'])
            
        return list(set(techniques))
    
    def _extract_platforms(self, logsource: Dict[str, Any]) -> List[str]:
        """Extract platforms from Sigma logsource"""
        platforms = []
        
        if 'product' in logsource:
            product = logsource['product'].lower()
            platform_map = {
                'windows': 'windows',
                'linux': 'linux',
                'macos': 'macos',
                'mac': 'macos',
                'aws': 'aws',
                'azure': 'azure',
                'gcp': 'gcp',
                'okta': 'cloud',
                'zeek': 'network',
                'apache': 'application',
                'nginx': 'application'
            }
            platforms.append(platform_map.get(product, product))
            
        return platforms if platforms else ['generic']
    
    def _extract_data_sources(self, logsource: Dict[str, Any]) -> List[str]:
        """Extract data sources from Sigma logsource"""
        sources = []
        
        for key in ['service', 'category', 'product']:
            if key in logsource:
                sources.append(f"{key}:{logsource[key]}")
                
        return sources if sources else ['unknown']
    
    def _extract_cves(self, rule: Dict[str, Any]) -> List[str]:
        """Extract CVE references from rule"""
        cve_pattern = r'CVE-\d{4}-\d{4,}'
        cves = []
        
        # Check description
        if 'description' in rule:
            cves.extend(re.findall(cve_pattern, rule['description']))
            
        # Check references
        for ref in rule.get('references', []):
            if isinstance(ref, str):
                cves.extend(re.findall(cve_pattern, ref))
                
        return list(set(cves))
    
    def _generate_hash(self, rule: Dict[str, Any]) -> str:
        """Generate deterministic hash for rule content"""
        content = json.dumps(rule.get('detection', {}), sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def _generate_ruleset_id(self, rules_data: Dict[str, Any]) -> str:
        """Generate unique ID for this ruleset import"""
        source = rules_data.get('source', 'unknown')
        timestamp = rules_data.get('collection_time', datetime.now(timezone.utc).isoformat())
        return hashlib.sha256(f"{source}:{timestamp}".encode()).hexdigest()[:16]


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
        s3_bucket = detail.get('s3_bucket', STAGING_BUCKET)
        s3_key = detail.get('s3_key')
        
        if not s3_key:
            raise ValueError("No S3 key provided")
            
        logger.info(f"Processing Sigma ruleset {ruleset_id} from s3://{s3_bucket}/{s3_key}")
        
        # Download rules from S3
        response = s3_client.get_object(Bucket=s3_bucket, Key=s3_key)
        rules_data = json.loads(response['Body'].read())
        
        logger.info(f"Loaded {rules_data.get('total_rules', 0)} rules")
        
        # Parse rules
        parser = SigmaParser()
        parsed_data = parser.parse_ruleset(rules_data)
        
        # Store parsed rules in S3
        parsed_key = s3_key.replace('rulesets/', 'parsed/').replace('.json', '_parsed.json')
        s3_client.put_object(
            Bucket=s3_bucket,
            Key=parsed_key,
            Body=json.dumps(parsed_data),
            ContentType='application/json',
            Metadata={
                'ruleset_id': parsed_data['ruleset_id'],
                'source': 'sigma',
                'parser_version': '1.0',
                'rule_count': str(len(parsed_data['rules']))
            }
        )
        
        # Publish event for universal processor
        event_detail = {
            'ruleset_id': parsed_data['ruleset_id'],
            'source': 'sigma',
            's3_bucket': s3_bucket,
            's3_key': parsed_key,
            'rule_count': len(parsed_data['rules']),
            'statistics': parsed_data['statistics'],
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        eventbridge_client.put_events(
            Entries=[{
                'Source': 'rules.parser.sigma',
                'DetailType': 'com.security.rules.parsed',
                'Detail': json.dumps(event_detail),
                'EventBusName': EVENT_BUS
            }]
        )
        
        duration = (datetime.now(timezone.utc) - start_time).total_seconds()
        
        logger.info(f"Successfully parsed {len(parsed_data['rules'])} rules in {duration:.2f}s")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Sigma rules parsed successfully',
                'ruleset_id': parsed_data['ruleset_id'],
                'rules_parsed': len(parsed_data['rules']),
                'statistics': parsed_data['statistics'],
                's3_location': f"s3://{s3_bucket}/{parsed_key}",
                'duration_seconds': duration
            })
        }
        
    except Exception as e:
        logger.error(f"Processing failed: {e}", exc_info=True)
        
        # Publish failure event
        try:
            eventbridge_client.put_events(
                Entries=[{
                    'Source': 'rules.parser.sigma',
                    'DetailType': 'com.security.rules.failed',
                    'Detail': json.dumps({
                        'ruleset_id': detail.get('ruleset_id', 'unknown'),
                        'error': str(e),
                        'failure_type': 'parse_failed',
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