"""
pano-snort-parser/lambda_function.py
Parses Snort rules to intermediate format for universal processor
"""
import json
import logging
import os
import boto3
import hashlib
import re
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3_client = boto3.client('s3')
eventbridge_client = boto3.client('events')

STAGING_BUCKET = os.environ.get('STAGING_BUCKET', 'panorama-rulesets')
EVENT_BUS = os.environ.get('EVENT_BUS', 'default')


class SnortParser:
    """Parse Snort rules to intermediate format"""
    
    def __init__(self):
        self.stats = {
            'total': 0,
            'parsed': 0,
            'errors': 0
        }
    
    def parse_ruleset(self, rules_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse entire ruleset to intermediate format"""
        parsed_rules = []
        ruleset_id = self._generate_ruleset_id(rules_data)
        
        for category, rules in rules_data.get('rules', {}).items():
            for rule in rules:
                self.stats['total'] += 1
                try:
                    parsed = self._parse_rule(rule)
                    if parsed:
                        parsed_rules.append(parsed)
                        self.stats['parsed'] += 1
                except Exception as e:
                    logger.error(f"Failed to parse rule: {e}")
                    self.stats['errors'] += 1
        
        return {
            'ruleset_id': ruleset_id,
            'source': 'snort',
            'parser_version': '1.0',
            'parsed_at': datetime.now(timezone.utc).isoformat(),
            'statistics': self.stats,
            'rules': parsed_rules
        }
    
    def _parse_rule(self, rule: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse single Snort rule to intermediate format"""
        if not rule.get('rule_id'):
            return None
        
        # Parse Snort rule structure
        severity = self._determine_severity(rule)
        
        parsed = {
            'original_id': rule['rule_id'],
            'title': rule.get('name', 'Snort Rule'),
            'description': self._extract_description(rule),
            'severity': severity,
            'confidence_score': 0.7,
            'tags': self._extract_tags(rule),
            'mitre_techniques': [],
            'false_positives': [],
            'references': self._extract_references(rule),
            'source': 'snort',
            'source_version': '3.0',
            'status': 'active',
            
            'detection_logic': {
                'format': 'snort',
                'content': rule.get('rule_content', ''),
                'action': rule.get('action', 'alert'),
                'protocol': rule.get('protocol', 'ip'),
                'source_ip': rule.get('source_ip', 'any'),
                'destination_ip': rule.get('destination_ip', 'any'),
                'destination_port': rule.get('destination_port', 'any')
            },
            
            'metadata': {
                'original_author': '',
                'original_date': '',
                'file_path': rule.get('file_path', ''),
                'content_hash': hashlib.sha256(
                    rule.get('rule_content', '').encode()
                ).hexdigest()[:16],
                'platforms': ['network'],
                'data_sources': ['network:traffic']
            }
        }
        
        # Extract CVE references
        cves = self._extract_cves(rule)
        if cves:
            parsed['cve_references'] = cves
        
        return parsed
    
    def _determine_severity(self, rule: Dict[str, Any]) -> str:
        """Determine severity from Snort rule priority"""
        priority = rule.get('priority', 3)
        if priority <= 1:
            return 'critical'
        elif priority == 2:
            return 'high'
        elif priority == 3:
            return 'medium'
        else:
            return 'low'
    
    def _extract_description(self, rule: Dict[str, Any]) -> str:
        """Extract description from rule options"""
        options = rule.get('options', '')
        msg_match = re.search(r'msg:"([^"]+)"', options)
        if msg_match:
            return msg_match.group(1)
        return rule.get('name', '')
    
    def _extract_tags(self, rule: Dict[str, Any]) -> List[str]:
        """Extract tags from rule metadata"""
        tags = []
        
        # Add protocol as tag
        if rule.get('protocol'):
            tags.append(f"protocol:{rule['protocol']}")
        
        # Add action as tag
        if rule.get('action'):
            tags.append(f"action:{rule['action']}")
        
        # Extract classtype
        options = rule.get('options', '')
        classtype_match = re.search(r'classtype:([^;]+)', options)
        if classtype_match:
            tags.append(f"classtype:{classtype_match.group(1)}")
        
        return tags
    
    def _extract_references(self, rule: Dict[str, Any]) -> List[str]:
        """Extract references from rule options"""
        references = []
        options = rule.get('options', '')
        
        # Extract reference URLs
        ref_matches = re.findall(r'reference:([^;]+)', options)
        for ref in ref_matches:
            references.append(ref.strip())
        
        return references
    
    def _extract_cves(self, rule: Dict[str, Any]) -> List[str]:
        """Extract CVE references"""
        cve_pattern = r'CVE-\d{4}-\d{4,}'
        cves = []
        
        # Check options and references
        text = f"{rule.get('options', '')} {' '.join(rule.get('references', []))}"
        cves.extend(re.findall(cve_pattern, text))
        
        return list(set(cves))
    
    def _generate_ruleset_id(self, rules_data: Dict[str, Any]) -> str:
        """Generate unique ID for this ruleset import"""
        source = rules_data.get('source', 'snort')
        timestamp = rules_data.get('downloaded_at', datetime.now(timezone.utc).isoformat())
        return hashlib.sha256(f"{source}:{timestamp}".encode()).hexdigest()[:16]


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda entry point for EventBridge events"""
    start_time = datetime.now(timezone.utc)
    
    try:
        # Parse EventBridge event
        detail = event.get('detail', {})
        if not detail:
            detail = event
        
        ruleset_id = detail.get('ruleset_id')
        s3_bucket = detail.get('s3_bucket', STAGING_BUCKET)
        s3_key = detail.get('s3_key')
        
        if not s3_key:
            raise ValueError("No S3 key provided")
        
        logger.info(f"Processing Snort ruleset {ruleset_id} from s3://{s3_bucket}/{s3_key}")
        
        # Download rules from S3
        response = s3_client.get_object(Bucket=s3_bucket, Key=s3_key)
        rules_data = json.loads(response['Body'].read())
        
        # Parse rules
        parser = SnortParser()
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
                'source': 'snort',
                'parser_version': '1.0',
                'rule_count': str(len(parsed_data['rules']))
            }
        )
        
        # Publish event for universal processor
        event_detail = {
            'ruleset_id': parsed_data['ruleset_id'],
            'source': 'snort',
            's3_bucket': s3_bucket,
            's3_key': parsed_key,
            'rule_count': len(parsed_data['rules']),
            'statistics': parsed_data['statistics'],
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        eventbridge_client.put_events(
            Entries=[{
                'Source': 'rules.parser.snort',
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
                'message': 'Snort rules parsed successfully',
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
                    'Source': 'rules.parser.snort',
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