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
from typing import Dict, List, Any, Optional, Tuple

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3_client = boto3.client('s3')
eventbridge_client = boto3.client('events')

STAGING_BUCKET = os.environ.get('STAGING_BUCKET', 'panorama-rulesets')
EVENT_BUS = os.environ.get('EVENT_BUS', 'default')


class SnortRuleParser:
    """Parse individual Snort rules"""
    
    CLASSTYPE_SEVERITY = {
        'trojan-activity': 'critical',
        'unsuccessful-admin': 'high',
        'successful-admin': 'critical',
        'attempted-admin': 'high',
        'successful-user': 'high',
        'attempted-user': 'medium',
        'unsuccessful-user': 'medium',
        'web-application-attack': 'high',
        'attempted-dos': 'high',
        'successful-dos': 'critical',
        'attempted-recon': 'low',
        'successful-recon-limited': 'low',
        'successful-recon-largescale': 'medium',
        'denial-of-service': 'high',
        'rpc-portmap-decode': 'medium',
        'suspicious-filename-detect': 'medium',
        'suspicious-login': 'medium',
        'system-call-detect': 'low',
        'network-scan': 'low',
        'protocol-command-decode': 'low',
        'misc-activity': 'info',
        'misc-attack': 'medium',
        'policy-violation': 'info',
        'default-login-attempt': 'medium',
        'bad-unknown': 'medium',
        'string-detect': 'low',
        'unknown': 'info'
    }
    
    def parse_rule(self, rule_line: str, file_path: str = '') -> Optional[Dict[str, Any]]:
        """Parse single Snort rule line"""
        rule_line = rule_line.strip()
        
        if not rule_line or rule_line.startswith('#'):
            return None
        
        # Extract basic structure: action proto src -> dst (options)
        match = re.match(
            r'^(\w+)\s+(\w+)\s+([^\s]+)\s+([^\s]+)\s+->\s+([^\s]+)\s+([^\s]+)\s+\((.*)\),
            rule_line
        )
        
        if not match:
            return None
        
        action, protocol, src_ip, src_port, dst_ip, dst_port, options_str = match.groups()
        
        # Parse options
        options = self._parse_options(options_str)
        
        # Extract key fields
        sid = options.get('sid', '')
        if not sid:
            return None
            
        msg = options.get('msg', '').strip('"')
        classtype = options.get('classtype', 'unknown')
        
        # Parse references
        references = []
        for key, value in options.items():
            if key == 'reference':
                references.append(value)
        
        # Extract CVEs from references
        cves = self._extract_cves(msg, references)
        
        # Determine severity
        severity = self._determine_severity(classtype, options)
        
        return {
            'sid': sid,
            'action': action,
            'protocol': protocol,
            'source_ip': src_ip,
            'source_port': src_port,
            'destination_ip': dst_ip,
            'destination_port': dst_port,
            'message': msg,
            'classtype': classtype,
            'severity': severity,
            'options': options,
            'references': references,
            'cves': cves,
            'raw_rule': rule_line,
            'file_path': file_path
        }
    
    def _parse_options(self, options_str: str) -> Dict[str, Any]:
        """Parse Snort rule options"""
        options = {}
        
        # Split by semicolon but handle quoted strings
        parts = re.split(r';\s*', options_str)
        
        for part in parts:
            part = part.strip()
            if not part:
                continue
                
            # Handle key:value pairs
            if ':' in part:
                key, value = part.split(':', 1)
                key = key.strip()
                value = value.strip()
                
                # Handle multiple values for same key (e.g., multiple references)
                if key == 'reference':
                    if 'reference' not in options:
                        options['reference'] = []
                    options['reference'].append(value)
                else:
                    options[key] = value
            else:
                # Boolean flag
                options[part] = True
        
        return options
    
    def _extract_cves(self, msg: str, references: List[str]) -> List[str]:
        """Extract CVE IDs from message and references"""
        cve_pattern = r'CVE-\d{4}-\d{4,}'
        cves = set()
        
        # Check message
        cves.update(re.findall(cve_pattern, msg, re.IGNORECASE))
        
        # Check references
        for ref in references:
            cves.update(re.findall(cve_pattern, ref, re.IGNORECASE))
        
        return list(cves)
    
    def _determine_severity(self, classtype: str, options: Dict) -> str:
        """Determine rule severity"""
        # Check priority if specified
        if 'priority' in options:
            priority = int(options['priority'])
            if priority == 1:
                return 'critical'
            elif priority == 2:
                return 'high'
            elif priority == 3:
                return 'medium'
            else:
                return 'low'
        
        # Use classtype mapping
        return self.CLASSTYPE_SEVERITY.get(classtype, 'medium')


class SnortParser:
    """Parse Snort rulesets to intermediate format"""
    
    def __init__(self):
        self.rule_parser = SnortRuleParser()
        self.stats = {
            'total': 0,
            'parsed': 0,
            'errors': 0,
            'files': set()
        }
    
    def parse_ruleset(self, rules_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse entire ruleset to intermediate format"""
        parsed_rules = []
        ruleset_id = self._generate_ruleset_id(rules_data)
        
        # Process all rules
        for category, rules in rules_data.get('rules', {}).items():
            self.stats['files'].add(category)
            
            for rule in rules:
                self.stats['total'] += 1
                try:
                    # Parse if we have raw rule content
                    if 'rule_content' in rule:
                        parsed_rule = self.rule_parser.parse_rule(
                            rule['rule_content'],
                            rule.get('file_path', '')
                        )
                        if parsed_rule:
                            # Convert to intermediate format
                            intermediate = self._to_intermediate_format(parsed_rule)
                            parsed_rules.append(intermediate)
                            self.stats['parsed'] += 1
                    elif 'raw_rule' in rule:
                        # Already parsed format from downloader
                        intermediate = self._normalize_downloaded_rule(rule)
                        parsed_rules.append(intermediate)
                        self.stats['parsed'] += 1
                        
                except Exception as e:
                    logger.error(f"Failed to parse rule: {e}")
                    self.stats['errors'] += 1
        
        return {
            'ruleset_id': ruleset_id,
            'source': 'snort',
            'parser_version': '1.0',
            'parsed_at': datetime.now(timezone.utc).isoformat(),
            'statistics': {
                'total': self.stats['total'],
                'parsed': self.stats['parsed'],
                'errors': self.stats['errors'],
                'files': list(self.stats['files'])
            },
            'rules': parsed_rules
        }
    
    def _to_intermediate_format(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        """Convert parsed Snort rule to intermediate format"""
        # Build title from message or SID
        title = rule.get('message', f"Snort Rule SID:{rule.get('sid', 'unknown')}")
        
        # Extract MITRE techniques if present in references
        mitre_techniques = self._extract_mitre_techniques(rule.get('references', []))
        
        # Build tags
        tags = [
            f"action:{rule.get('action', 'alert')}",
            f"protocol:{rule.get('protocol', 'ip')}",
            f"classtype:{rule.get('classtype', 'unknown')}"
        ]
        
        # Add flow direction if present
        if 'flow' in rule.get('options', {}):
            tags.append(f"flow:{rule['options']['flow']}")
        
        return {
            'original_id': f"snort:{rule.get('sid', '')}",
            'title': title,
            'description': self._build_description(rule),
            'severity': rule.get('severity', 'medium'),
            'confidence_score': 0.8,  # Snort rules are generally reliable
            'tags': tags,
            'mitre_techniques': mitre_techniques,
            'false_positives': [],
            'references': rule.get('references', []),
            'cve_references': rule.get('cves', []),
            'source': 'snort',
            'source_version': '3.0',
            'status': 'active',
            
            'detection_logic': {
                'format': 'snort',
                'content': rule.get('raw_rule', ''),
                'parsed': {
                    'action': rule.get('action'),
                    'protocol': rule.get('protocol'),
                    'source_ip': rule.get('source_ip'),
                    'source_port': rule.get('source_port'),
                    'destination_ip': rule.get('destination_ip'),
                    'destination_port': rule.get('destination_port'),
                    'options': rule.get('options', {})
                }
            },
            
            'metadata': {
                'sid': rule.get('sid', ''),
                'classtype': rule.get('classtype', ''),
                'file_path': rule.get('file_path', ''),
                'content_hash': hashlib.sha256(
                    rule.get('raw_rule', '').encode()
                ).hexdigest()[:16],
                'platforms': ['network'],
                'data_sources': ['network:traffic']
            }
        }
    
    def _normalize_downloaded_rule(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize rule already processed by downloader"""
        return {
            'original_id': f"snort:{rule.get('rule_id', '')}",
            'title': rule.get('name', 'Snort Rule'),
            'description': f"Protocol: {rule.get('protocol', 'any')}, "
                          f"Source: {rule.get('source_ip', 'any')}:{rule.get('source_port', 'any')}, "
                          f"Dest: {rule.get('destination_ip', 'any')}:{rule.get('destination_port', 'any')}",
            'severity': 'medium',
            'confidence_score': 0.7,
            'tags': [f"action:{rule.get('action', 'alert')}"],
            'mitre_techniques': [],
            'false_positives': [],
            'references': [],
            'source': 'snort',
            'source_version': '3.0',
            'status': 'active',
            
            'detection_logic': {
                'format': 'snort',
                'content': rule.get('rule_content', '')
            },
            
            'metadata': {
                'original_id': rule.get('rule_id', ''),
                'content_hash': hashlib.sha256(
                    rule.get('rule_content', '').encode()
                ).hexdigest()[:16],
                'platforms': ['network'],
                'data_sources': ['network:traffic']
            }
        }
    
    def _build_description(self, rule: Dict[str, Any]) -> str:
        """Build descriptive text for rule"""
        parts = []
        
        # Add basic flow info
        parts.append(
            f"{rule.get('action', 'Alert')} on {rule.get('protocol', 'any')} traffic"
        )
        
        # Add source/dest info
        src = f"{rule.get('source_ip', 'any')}:{rule.get('source_port', 'any')}"
        dst = f"{rule.get('destination_ip', 'any')}:{rule.get('destination_port', 'any')}"
        parts.append(f"from {src} to {dst}")
        
        # Add classtype if present
        if rule.get('classtype'):
            parts.append(f"Class: {rule['classtype']}")
        
        return ". ".join(parts)
    
    def _extract_mitre_techniques(self, references: List[str]) -> List[str]:
        """Extract MITRE ATT&CK techniques from references"""
        techniques = []
        
        for ref in references:
            # Look for MITRE references
            if 'attack.mitre.org' in ref:
                match = re.search(r'T\d{4}(?:\.\d{3})?', ref)
                if match:
                    techniques.append(match.group())
        
        return techniques
    
    def _generate_ruleset_id(self, rules_data: Dict[str, Any]) -> str:
        """Generate unique ID for this ruleset import"""
        source = rules_data.get('source', 'snort')
        timestamp = rules_data.get('downloaded_at', datetime.now(timezone.utc).isoformat())
        return hashlib.sha256(f"{source}:{timestamp}".encode()).hexdigest()[:16]


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda entry point for EventBridge events"""
    start_time = datetime.now(timezone.utc)
    
    try:
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
        
        # Store parsed rules
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
        
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': 'Processing failed',
                'message': str(e),
                'timestamp': start_time.isoformat()
            })
        }