"""
pano-sigma-parser/lambda_function.py
Parses Sigma rules from downloader output to normalized format
"""
import json
import logging
import os
import boto3
import hashlib
import re
import yaml
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3_client = boto3.client('s3')
eventbridge_client = boto3.client('events')

STAGING_BUCKET = os.environ.get('STAGING_BUCKET', 'panorama-rulesets')
EVENT_BUS = os.environ.get('EVENT_BUS', 'panorama-rules-processing')


class SigmaParser:
    """Parse Sigma YAML rules to normalized format"""
    
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
            'categories': {},
            'invalid_yaml': 0,
            'missing_fields': 0
        }
    
    def parse_rules(self, rules_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse Sigma rules from downloader output"""
        
        parsed_rules = []
        categories = rules_data.get('categories', {})
        
        for category_name, category_data in categories.items():
            category_rules = category_data.get('rules', [])
            self.stats['categories'][category_name] = {
                'total': len(category_rules),
                'parsed': 0,
                'errors': 0
            }
            
            for rule_entry in category_rules:
                self.stats['total'] += 1
                
                try:
                    # Parse YAML content
                    parsed_yaml = self._parse_yaml_content(rule_entry['content'])
                    if not parsed_yaml:
                        self.stats['invalid_yaml'] += 1
                        self.stats['errors'] += 1
                        self.stats['categories'][category_name]['errors'] += 1
                        continue
                    
                    # Normalize to common format
                    normalized = self._normalize_rule(parsed_yaml, rule_entry, category_name)
                    if normalized:
                        parsed_rules.append(normalized)
                        self.stats['parsed'] += 1
                        self.stats['categories'][category_name]['parsed'] += 1
                    else:
                        self.stats['missing_fields'] += 1
                        self.stats['errors'] += 1
                        self.stats['categories'][category_name]['errors'] += 1
                        
                except Exception as e:
                    logger.debug(f"Failed to parse {rule_entry.get('filename', 'unknown')}: {e}")
                    self.stats['errors'] += 1
                    self.stats['categories'][category_name]['errors'] += 1
        
        return parsed_rules
    
    def _parse_yaml_content(self, content: str) -> Optional[Dict]:
        """Parse YAML content safely"""
        
        try:
            # Handle multiple documents in single file
            documents = list(yaml.safe_load_all(content))
            # Return first valid document (Sigma rules are typically single-doc)
            return documents[0] if documents else None
        except yaml.YAMLError as e:
            logger.debug(f"YAML parse error: {e}")
            return None
    
    def _normalize_rule(self, rule: Dict, rule_entry: Dict, category: str) -> Optional[Dict[str, Any]]:
        """Normalize Sigma rule to common format"""
        
        # Validate required fields
        if not self._validate_rule(rule):
            return None
        
        # Extract rule ID
        rule_id = rule.get('id', hashlib.md5(rule_entry['content'].encode()).hexdigest())
        
        # Extract basic fields
        title = rule.get('title', 'Untitled Sigma Rule')
        description = rule.get('description', '')
        
        # Determine severity
        level = rule.get('level', 'medium')
        severity = self.SEVERITY_MAP.get(level, 'medium')
        
        # Calculate confidence score
        status = rule.get('status', 'experimental')
        confidence_score = self.STATUS_CONFIDENCE.get(status, 0.5)
        
        # Extract MITRE techniques
        mitre_techniques = self._extract_mitre_techniques(rule)
        
        # Extract logsource info
        logsource = rule.get('logsource', {})
        platforms = self._extract_platforms(logsource)
        data_sources = self._extract_data_sources(logsource)
        
        # Build tags
        tags = self._build_tags(rule, category)
        
        # Extract references
        references = rule.get('references', [])
        
        # Extract false positives
        false_positives = rule.get('falsepositives', [])
        
        return {
            'original_id': f"sigma:{rule_id}",
            'title': title,
            'description': description,
            'severity': severity,
            'confidence_score': confidence_score,
            'tags': tags,
            'mitre_techniques': mitre_techniques,
            'false_positives': false_positives,
            'references': references,
            'cve_references': [],  # Sigma rules rarely contain direct CVE refs
            'source': 'sigma',
            'source_version': rule.get('modified', rule.get('date', '')),
            'status': 'active' if status != 'deprecated' else 'inactive',
            
            'detection_logic': {
                'format': 'sigma',
                'content': yaml.dump(rule.get('detection', {})),
                'raw_rule': rule_entry['content'],
                'parsed': {
                    'detection': rule.get('detection', {}),
                    'logsource': logsource,
                    'timeframe': rule.get('detection', {}).get('timeframe')
                }
            },
            
            'metadata': {
                'rule_id': rule_id,
                'status': status,
                'level': level,
                'author': rule.get('author', 'Unknown'),
                'date': str(rule.get('date', '')),
                'modified': str(rule.get('modified', '')),
                'file_path': rule_entry.get('path', ''),
                'filename': rule_entry.get('filename', ''),
                'category': category,
                'content_hash': rule_entry.get('sha256', '')[:16],
                'platforms': platforms,
                'data_sources': data_sources,
                'logsource_product': logsource.get('product'),
                'logsource_service': logsource.get('service'),
                'logsource_category': logsource.get('category'),
                'related': rule.get('related', [])
            }
        }
    
    def _validate_rule(self, rule: Dict) -> bool:
        """Validate Sigma rule has required fields"""
        
        # Must have title and detection
        if not rule.get('title') or not rule.get('detection'):
            return False
        
        # Detection must have at least one condition
        detection = rule.get('detection', {})
        if not detection.get('condition'):
            return False
        
        return True
    
    def _extract_mitre_techniques(self, rule: Dict) -> List[str]:
        """Extract raw MITRE ATT&CK tags for enricher processing"""
        
        techniques = []
        tags = rule.get('tags', [])
        
        for tag in tags:
            if isinstance(tag, str) and tag.startswith('attack.'):
                # Preserve original tag format for enricher
                techniques.append(tag)
        
        return techniques
    
    def _extract_platforms(self, logsource: Dict) -> List[str]:
        """Extract target platforms from logsource"""
        
        platforms = []
        
        product = logsource.get('product', '').lower()
        service = logsource.get('service', '').lower()
        category = logsource.get('category', '').lower()
        
        # Map products to platforms
        if product == 'windows' or service in ['security', 'system', 'sysmon']:
            platforms.append('windows')
        elif product == 'linux' or service in ['auditd', 'syslog']:
            platforms.append('linux')
        elif product == 'macos':
            platforms.append('macos')
        elif product in ['aws', 'azure', 'gcp']:
            platforms.append('cloud')
        elif category == 'firewall' or product == 'firewall':
            platforms.append('network')
        elif category == 'webserver' or service in ['apache', 'nginx', 'iis']:
            platforms.append('web')
        
        # Default to generic if no specific platform
        if not platforms:
            platforms.append('generic')
        
        return platforms
    
    def _extract_data_sources(self, logsource: Dict) -> List[str]:
        """Extract data sources from logsource"""
        
        sources = []
        
        product = logsource.get('product')
        service = logsource.get('service')
        category = logsource.get('category')
        
        if product:
            sources.append(f"product:{product}")
        if service:
            sources.append(f"service:{service}")
        if category:
            sources.append(f"category:{category}")
        
        # Add specific data source mappings
        if service == 'sysmon':
            sources.append('sysmon:process_creation')
        elif service == 'security':
            sources.append('windows:security')
        elif service == 'auditd':
            sources.append('linux:auditd')
        
        return sources if sources else ['logs:generic']
    
    def _build_tags(self, rule: Dict, category: str) -> List[str]:
        """Build tags from rule and metadata"""
        
        tags = []
        
        # Add original tags
        original_tags = rule.get('tags', [])
        for tag in original_tags:
            if isinstance(tag, str) and not tag.startswith('attack.'):
                tags.append(tag)
        
        # Add status tag
        status = rule.get('status')
        if status:
            tags.append(f"status:{status}")
        
        # Add level tag
        level = rule.get('level')
        if level:
            tags.append(f"level:{level}")
        
        # Add category tag
        tags.append(f"category:{category}")
        
        # Add logsource tags
        logsource = rule.get('logsource', {})
        if logsource.get('product'):
            tags.append(f"product:{logsource['product']}")
        if logsource.get('service'):
            tags.append(f"service:{logsource['service']}")
        
        # Add detection type tag
        tags.append("detection:sigma")
        
        return list(set(tags))


def lambda_handler(event, context):
    """Lambda handler for Sigma rule parsing"""
    
    try:
        # Parse EventBridge event
        detail = json.loads(event.get('detail', '{}')) if isinstance(event.get('detail'), str) else event.get('detail', {})
        
        s3_bucket = detail.get('s3_bucket', STAGING_BUCKET)
        s3_key = detail.get('s3_key')
        ruleset_id = detail.get('ruleset_id')
        
        if not s3_key:
            raise ValueError("Missing s3_key in event detail")
        
        logger.info(f"Processing Sigma ruleset {ruleset_id} from s3://{s3_bucket}/{s3_key}")
        
        # Download rules data from S3
        response = s3_client.get_object(Bucket=s3_bucket, Key=s3_key)
        rules_data = json.loads(response['Body'].read())
        
        # Parse rules
        parser = SigmaParser()
        parsed_rules = parser.parse_rules(rules_data)
        
        # Upload parsed rules to S3
        parsed_key = s3_key.replace('/rules.json', '/parsed.json')
        
        parsed_data = {
            'source': 'sigma',
            'ruleset_id': ruleset_id,
            'parsed_at': datetime.now(timezone.utc).isoformat(),
            'statistics': parser.stats,
            'rules': parsed_rules
        }
        
        s3_client.put_object(
            Bucket=s3_bucket,
            Key=parsed_key,
            Body=json.dumps(parsed_data),
            ContentType='application/json',
            Metadata={
                'source': 'sigma',
                'ruleset_id': ruleset_id,
                'rule_count': str(len(parsed_rules))
            }
        )
        
        # Publish event for universal processor
        eventbridge_client.put_events(
            Entries=[{
                'Source': 'rules.parser.sigma',
                'DetailType': 'com.security.rules.parsed',
                'Detail': json.dumps({
                    'ruleset_id': ruleset_id,
                    'source': 'sigma',
                    's3_bucket': s3_bucket,
                    's3_key': parsed_key,
                    'rule_count': len(parsed_rules),
                    'statistics': parser.stats,
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }),
                'EventBusName': EVENT_BUS
            }]
        )
        
        logger.info(f"Successfully parsed {len(parsed_rules)} Sigma rules")
        logger.info(f"Statistics: {json.dumps(parser.stats)}")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Sigma rules parsed successfully',
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
                'Source': 'rules.parser.sigma',
                'DetailType': 'com.security.rules.parse.failed',
                'Detail': json.dumps({
                    'ruleset_id': detail.get('ruleset_id', 'unknown'),
                    'source': 'sigma',
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