"""
pano-snort-parser/lambda_function.py
Parses Snort rules and normalizes them for the universal processor
"""
import json
import logging
import os
import boto3
import tempfile
import tarfile
import hashlib
import re
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from pathlib import Path

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3_client = boto3.client('s3')
eventbridge_client = boto3.client('events')

STAGING_BUCKET = os.environ.get('STAGING_BUCKET', 'panorama-rulesets')
EVENT_BUS = os.environ.get('EVENT_BUS', 'panorama-rules-processing')

class SnortRuleParser:
    """Parse and normalize Snort rules"""
    
    # Snort rule pattern - handles standard format
    RULE_PATTERN = re.compile(
        r'^(alert|log|pass|drop|reject|sdrop)\s+'  # action
        r'(\S+)\s+'                                  # protocol
        r'(\S+)\s+(\S+)\s+'                         # src addr/port
        r'(->|<>)\s+'                                # direction
        r'(\S+)\s+(\S+)\s+'                         # dst addr/port
        r'\((.*)\)$',                                # options
        re.DOTALL
    )
    
    # Option patterns
    SID_PATTERN = re.compile(r'sid:\s*(\d+)')
    MSG_PATTERN = re.compile(r'msg:\s*"([^"]+)"')
    CLASSTYPE_PATTERN = re.compile(r'classtype:\s*([^;]+)')
    PRIORITY_PATTERN = re.compile(r'priority:\s*(\d+)')
    REF_PATTERN = re.compile(r'reference:\s*([^;]+)')
    CVE_PATTERN = re.compile(r'cve[,-]\d{4}-\d+', re.IGNORECASE)
    

    
    def __init__(self):
        self.stats = {
            'parsed': 0,
            'failed': 0,
            'total': 0
        }
    
    def parse_rules(self, rules_content: str) -> List[Dict[str, Any]]:
        """Parse Snort rules from content"""
        
        parsed_rules = []
        current_rule = []
        
        for line in rules_content.split('\n'):
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue
            
            # Handle multi-line rules
            if line.endswith('\\'):
                current_rule.append(line[:-1])
                continue
            
            # Complete rule
            if current_rule:
                line = ' '.join(current_rule) + ' ' + line
                current_rule = []
            
            # Parse rule
            parsed = self._parse_single_rule(line)
            if parsed:
                parsed_rules.append(parsed)
                self.stats['parsed'] += 1
            else:
                self.stats['failed'] += 1
            
            self.stats['total'] += 1
        
        return parsed_rules
    
    def _parse_single_rule(self, rule_line: str) -> Optional[Dict[str, Any]]:
        """Parse a single Snort rule"""
        
        match = self.RULE_PATTERN.match(rule_line)
        if not match:
            logger.debug(f"Failed to parse: {rule_line[:100]}")
            return None
        
        action, protocol, src_addr, src_port, direction, dst_addr, dst_port, options = match.groups()
        
        # Parse options
        parsed_options = self._parse_options(options)
        
        # Extract key fields
        sid = self._extract_sid(parsed_options)
        if not sid:
            return None
        
        msg = self._extract_msg(parsed_options)
        classtype = parsed_options.get('classtype', 'unknown')
        priority = int(parsed_options.get('priority', '3'))
        
        # Map severity
        severity = self._map_severity(priority, classtype)
        
        # Extract MITRE techniques
        mitre_techniques = self._extract_mitre_techniques(classtype, msg)
        
        # Extract CVEs
        cves = self._extract_cves(parsed_options)
        
        # Extract references
        references = self._extract_references(parsed_options)
        
        return {
            'original_id': f"snort:{sid}",
            'title': msg or f"Snort Rule {sid}",
            'description': self._build_description(msg, classtype, action),
            'severity': severity,
            'confidence_score': 0.85,
            'tags': self._build_tags(action, protocol, classtype),
            'mitre_techniques': mitre_techniques,
            'false_positives': [],
            'references': references,
            'cve_references': cves,
            'source': 'snort',
            'source_version': '3.0',
            'status': 'active',
            
            'detection_logic': {
                'format': 'snort',
                'content': rule_line,
                'parsed': {
                    'action': action,
                    'protocol': protocol,
                    'source_address': src_addr,
                    'source_port': src_port,
                    'direction': direction,
                    'destination_address': dst_addr,
                    'destination_port': dst_port,
                    'options': parsed_options
                }
            },
            
            'metadata': {
                'sid': sid,
                'classtype': classtype,
                'priority': priority,
                'content_hash': hashlib.sha256(rule_line.encode()).hexdigest()[:16],
                'platforms': ['network'],
                'data_sources': ['network:traffic']
            }
        }
    
    def _parse_options(self, options_str: str) -> Dict[str, Any]:
        """Parse Snort rule options"""
        
        options = {}
        
        # Extract SID
        sid_match = self.SID_PATTERN.search(options_str)
        if sid_match:
            options['sid'] = sid_match.group(1)
        
        # Extract message
        msg_match = self.MSG_PATTERN.search(options_str)
        if msg_match:
            options['msg'] = msg_match.group(1)
        
        # Extract classtype
        classtype_match = self.CLASSTYPE_PATTERN.search(options_str)
        if classtype_match:
            options['classtype'] = classtype_match.group(1).strip()
        
        # Extract priority
        priority_match = self.PRIORITY_PATTERN.search(options_str)
        if priority_match:
            options['priority'] = priority_match.group(1)
        
        # Extract references
        references = []
        for ref_match in self.REF_PATTERN.finditer(options_str):
            references.append(ref_match.group(1).strip())
        if references:
            options['references'] = references
        
        # Extract flow, content, and other options
        if 'flow:' in options_str:
            flow_match = re.search(r'flow:\s*([^;]+)', options_str)
            if flow_match:
                options['flow'] = flow_match.group(1).strip()
        
        if 'content:' in options_str:
            content_matches = re.findall(r'content:\s*"([^"]+)"', options_str)
            if content_matches:
                options['content'] = content_matches
        
        return options
    
    def _extract_sid(self, options: Dict) -> Optional[str]:
        """Extract SID from options"""
        return options.get('sid')
    
    def _extract_msg(self, options: Dict) -> str:
        """Extract message from options"""
        return options.get('msg', '')
    
    def _map_severity(self, priority: int, classtype: str) -> str:
        """Map Snort priority/classtype to severity"""
        
        # High severity classtypes
        high_severity = [
            'trojan-activity', 'attempted-admin', 'successful-admin',
            'shellcode-detect', 'system-call-detect'
        ]
        
        # Low severity classtypes
        low_severity = [
            'policy-violation', 'protocol-command-decode',
            'string-detect', 'unknown'
        ]
        
        if classtype in high_severity or priority == 1:
            return 'critical'
        elif priority == 2:
            return 'high'
        elif classtype in low_severity or priority >= 4:
            return 'low'
        else:
            return 'medium'
    
    def _extract_mitre_techniques(self, classtype: str, msg: str) -> List[str]:
        """Extract potential MITRE indicators for enricher processing"""
        
        # Return classtype and message keywords as hints for the enricher
        # The MITRE enricher will do proper mapping using STIX database
        techniques = []
        
        # Preserve classtype for enricher
        if classtype:
            techniques.append(f"classtype:{classtype}")
        
        # Extract potential technique keywords from message
        msg_lower = msg.lower()
        keywords = [
            'command injection', 'sql injection', 'buffer overflow',
            'brute force', 'backdoor', 'phishing', 'privilege escalation',
            'lateral movement', 'persistence', 'credential', 'exfiltration'
        ]
        
        for keyword in keywords:
            if keyword in msg_lower:
                techniques.append(f"keyword:{keyword.replace(' ', '_')}")
        
        return techniques
    
    def _extract_cves(self, options: Dict) -> List[str]:
        """Extract CVE references from options"""
        
        cves = []
        references = options.get('references', [])
        
        for ref in references:
            cve_matches = self.CVE_PATTERN.findall(ref)
            cves.extend([cve.upper().replace(',', '-') for cve in cve_matches])
        
        return list(set(cves))
    
    def _extract_references(self, options: Dict) -> List[str]:
        """Extract and format references"""
        
        references = []
        raw_refs = options.get('references', [])
        
        for ref in raw_refs:
            if 'url,' in ref:
                url = ref.split('url,', 1)[1].strip()
                references.append(url)
            elif 'cve,' in ref.lower():
                # CVEs handled separately
                continue
            else:
                references.append(ref)
        
        return references
    
    def _build_description(self, msg: str, classtype: str, action: str) -> str:
        """Build rule description"""
        
        description = msg or f"Snort rule for {classtype}"
        
        if action != 'alert':
            description += f" (Action: {action})"
        
        return description
    
    def _build_tags(self, action: str, protocol: str, classtype: str) -> List[str]:
        """Build rule tags"""
        
        tags = [
            f"action:{action}",
            f"protocol:{protocol}",
            f"classtype:{classtype}",
            "ids:snort"
        ]
        
        return tags


def lambda_handler(event, context):
    """Lambda handler for Snort rule parsing"""
    
    try:
        # Parse EventBridge event
        detail = json.loads(event.get('detail', '{}')) if isinstance(event.get('detail'), str) else event.get('detail', {})
        
        s3_bucket = detail.get('s3_bucket', STAGING_BUCKET)
        s3_key = detail.get('s3_key')
        ruleset_id = detail.get('ruleset_id')
        
        if not s3_key:
            raise ValueError("Missing s3_key in event detail")
        
        logger.info(f"Processing Snort ruleset {ruleset_id} from s3://{s3_bucket}/{s3_key}")
        
        # Download and parse rules
        parser = SnortRuleParser()
        all_rules = []
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Download from S3
            tar_path = temp_path / 'snort-rules.tar.gz'
            s3_client.download_file(s3_bucket, s3_key, str(tar_path))
            
            # Extract and parse
            with tarfile.open(tar_path, 'r:gz') as tar:
                for member in tar.getmembers():
                    if member.name.endswith('.rules'):
                        content = tar.extractfile(member).read().decode('utf-8', errors='ignore')
                        rules = parser.parse_rules(content)
                        all_rules.extend(rules)
        
        # Upload parsed rules to S3
        parsed_key = s3_key.replace('/rules.tar.gz', '/parsed.json')
        
        parsed_data = {
            'source': 'snort',
            'ruleset_id': ruleset_id,
            'parsed_at': datetime.now(timezone.utc).isoformat(),
            'statistics': parser.stats,
            'rules': all_rules
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
                'Source': 'rules.parser.snort',
                'DetailType': 'com.security.rules.parsed',
                'Detail': json.dumps({
                    'ruleset_id': ruleset_id,
                    'source': 'snort',
                    's3_bucket': s3_bucket,
                    's3_key': parsed_key,
                    'rule_count': len(all_rules),
                    'statistics': parser.stats,
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }),
                'EventBusName': EVENT_BUS
            }]
        )
        
        logger.info(f"Successfully parsed {len(all_rules)} Snort rules")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Snort rules parsed successfully',
                'ruleset_id': ruleset_id,
                'rule_count': len(all_rules),
                'statistics': parser.stats
            })
        }
        
    except Exception as e:
        logger.error(f"Parsing failed: {e}", exc_info=True)
        
        # Publish failure event
        eventbridge_client.put_events(
            Entries=[{
                'Source': 'rules.parser.snort',
                'DetailType': 'com.security.rules.parse.failed',
                'Detail': json.dumps({
                    'ruleset_id': detail.get('ruleset_id', 'unknown'),
                    'source': 'snort',
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