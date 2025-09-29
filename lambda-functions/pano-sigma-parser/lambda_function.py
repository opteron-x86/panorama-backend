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
from datetime import datetime, date, timezone
from typing import Dict, List, Any, Optional

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3_client = boto3.client('s3')
eventbridge_client = boto3.client('events')

STAGING_BUCKET = os.environ.get('STAGING_BUCKET', 'panorama-rulesets')
EVENT_BUS = os.environ.get('EVENT_BUS', 'panorama-rules-processing')


class DateEncoder(json.JSONEncoder):
    """Custom JSON encoder to handle date/datetime objects"""
    def default(self, obj):
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        return super().default(obj)


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
        
        # Generate unique ID
        rule_id = self._generate_rule_id(rule_entry)
        
        # Extract key fields
        title = rule.get('title', 'Untitled')
        description = rule.get('description', '')
        status = rule.get('status', 'experimental')
        level = rule.get('level', 'medium')
        logsource = rule.get('logsource', {})
        
        # Convert dates to strings
        date_val = rule.get('date')
        if isinstance(date_val, (datetime, date)):
            date_str = date_val.isoformat()
        else:
            date_str = str(date_val) if date_val else ''
        
        modified_val = rule.get('modified')
        if isinstance(modified_val, (datetime, date)):
            modified_str = modified_val.isoformat()
        else:
            modified_str = str(modified_val) if modified_val else ''
        
        # Extract platforms and data sources
        platforms = self._extract_platforms(logsource)
        data_sources = self._extract_data_sources(logsource)
        
        # Extract MITRE techniques
        mitre_techniques = self._extract_mitre_techniques(rule)
        
        # Build tags
        tags = self._build_tags(rule, category)
        
        return {
            'original_id': rule_id,  # Changed from 'rule_id' to match normalized schema
            'source': 'sigma',
            'source_version': '1.0',
            
            'title': title,
            'description': description,
            'severity': self.SEVERITY_MAP.get(level, 'medium'),
            'confidence_score': self.STATUS_CONFIDENCE.get(status, 0.5),
            
            'tags': tags,
            'mitre_techniques': mitre_techniques,
            'platforms': platforms,
            'data_sources': data_sources,
            
            'false_positives': rule.get('falsepositives', []),
            'references': rule.get('references', []),
            
            'detection_logic': {
                'format': 'sigma',
                'content': self._sanitize_detection(rule.get('detection', {})),
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
                'date': date_str,
                'modified': modified_str,
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
    
    def _sanitize_detection(self, detection: Dict) -> Dict:
        """Sanitize detection logic to ensure JSON serializable"""
        if not detection:
            return {}
        
        # Convert any date objects in detection to strings
        def convert_dates(obj):
            if isinstance(obj, (datetime, date)):
                return obj.isoformat()
            elif isinstance(obj, dict):
                return {k: convert_dates(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_dates(item) for item in obj]
            return obj
        
        return convert_dates(detection)
    
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
                # Remove attack. prefix and format
                technique = tag.replace('attack.', '').upper()
                if technique.startswith('T') and technique[1:].split('.')[0].isdigit():
                    techniques.append(technique)
        
        return techniques
    
    def _generate_rule_id(self, rule_entry: Dict) -> str:
        """Generate unique rule ID"""
        
        # Use SHA256 hash if available
        if rule_entry.get('sha256'):
            return f"sigma_{rule_entry['sha256'][:16]}"
        
        # Fallback to hash of content
        content = rule_entry.get('content', '')
        hash_obj = hashlib.sha256(content.encode('utf-8'))
        return f"sigma_{hash_obj.hexdigest()[:16]}"
    
    def _extract_platforms(self, logsource: Dict) -> List[str]:
        """Extract platform information from logsource"""
        
        platforms = []
        product = logsource.get('product', '').lower()
        service = logsource.get('service', '').lower()
        
        # Map products to platforms
        if product in ['windows', 'windows-defender']:
            platforms.append('windows')
        elif product in ['linux', 'auditd', 'sysmon-linux']:
            platforms.append('linux')
        elif product in ['macos', 'mac']:
            platforms.append('macos')
        elif product in ['aws', 'amazon']:
            platforms.append('cloud:aws')
        elif product in ['azure', 'microsoft365', 'office365']:
            platforms.append('cloud:azure')
        elif product in ['gcp', 'google']:
            platforms.append('cloud:gcp')
        
        # Check services as fallback
        if not platforms and service:
            if 'windows' in service or 'powershell' in service:
                platforms.append('windows')
            elif 'linux' in service or 'ssh' in service:
                platforms.append('linux')
        
        return platforms or ['generic']
    
    def _extract_data_sources(self, logsource: Dict) -> List[str]:
        """Extract data source information"""
        
        sources = []
        product = logsource.get('product', '')
        service = logsource.get('service', '')
        category = logsource.get('category', '')
        
        if product:
            sources.append(f"product:{product}")
        if service:
            sources.append(f"service:{service}")
        if category:
            sources.append(f"category:{category}")
        
        return sources or ['unknown']
    
    def _build_tags(self, rule: Dict, category: str) -> List[str]:
        """Build comprehensive tag list"""
        
        tags = []
        
        # Add MITRE tags
        for tag in rule.get('tags', []):
            if isinstance(tag, str) and ('attack.' in tag or 'car.' in tag):
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
        
        # Use custom encoder for dates
        s3_client.put_object(
            Bucket=s3_bucket,
            Key=parsed_key,
            Body=json.dumps(parsed_data, cls=DateEncoder),
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
                }, cls=DateEncoder),
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