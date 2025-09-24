"""
Snort Community Rules Downloader Lambda
Downloads and stages Snort community rules for processing
"""
import json
import logging
import os
import boto3
import tempfile
import hashlib
import tarfile
import gzip
import urllib.request
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
import re

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3_client = boto3.client('s3')
lambda_client = boto3.client('lambda')

STAGING_BUCKET = os.environ.get('STAGING_BUCKET', 'panorama-rulesets-538269499906')
SNORT_PREFIX = 'snort'


class SnortRuleParser:
    """Parse individual Snort rules"""
    
    failed_rules = 0  # Track parsing failures for debugging
    
    # More flexible pattern - handle various formats
    RULE_PATTERN = re.compile(
        r'^(alert|log|pass|activate|dynamic|drop|reject|sdrop)\s+'
        r'([^\s]+)\s+'  # protocol
        r'([^\s]+)\s+'  # source address
        r'(->|<>|<-)\s+'  # direction
        r'([^\s]+)\s+'  # dest address
        r'([^\s]+)\s+'  # dest port
        r'\((.*)\)(?:\s*;)?$',  # options (may have trailing semicolon)
        re.DOTALL
    )
    
    # Alternative pattern for simpler format (3 fields before options)
    SIMPLE_PATTERN = re.compile(
        r'^(alert|log|pass|activate|dynamic|drop|reject|sdrop)\s+'
        r'([^\s]+)\s+'  # protocol
        r'([^\(]+)'  # everything before options
        r'\((.*)\)(?:\s*;)?$',
        re.DOTALL
    )
    
    SID_PATTERN = re.compile(r'sid:\s*(\d+)')
    REV_PATTERN = re.compile(r'rev:\s*(\d+)')
    MSG_PATTERN = re.compile(r'msg:\s*"([^"]+)"')
    REFERENCE_PATTERN = re.compile(r'reference:\s*([^;]+)')
    CLASSTYPE_PATTERN = re.compile(r'classtype:\s*([^;]+)')
    PRIORITY_PATTERN = re.compile(r'priority:\s*(\d+)')
    CVE_PATTERN = re.compile(r'(?:reference:\s*)?(?:cve|CVE)[,\s]+(\d{4}-\d+)')
    
    SEVERITY_MAP = {
        1: 'high',
        2: 'medium', 
        3: 'low',
        4: 'info'
    }
    
    CLASSTYPE_SEVERITY = {
        'trojan-activity': 'high',
        'attempted-admin': 'high',
        'successful-admin': 'critical',
        'attempted-user': 'medium',
        'successful-user': 'high',
        'attempted-recon': 'low',
        'successful-recon-limited': 'medium',
        'successful-recon-largescale': 'high',
        'attempted-dos': 'medium',
        'successful-dos': 'high',
        'web-application-attack': 'medium',
        'web-application-activity': 'low',
        'misc-attack': 'medium',
        'misc-activity': 'low',
        'policy-violation': 'low',
        'protocol-command-decode': 'low',
        'bad-unknown': 'medium',
        'suspicious-filename-detect': 'medium',
        'suspicious-login': 'medium',
        'system-call-detect': 'medium',
        'shellcode-detect': 'high',
        'rpc-portmap-decode': 'low',
        'denial-of-service': 'high',
        'network-scan': 'low',
        'not-suspicious': 'info',
        'unknown': 'medium'
    }
    
    @classmethod
    def parse_rule(cls, rule_text: str) -> Optional[Dict[str, Any]]:
        """Parse a single Snort rule"""
        
        # Skip comments and empty lines
        rule_text = rule_text.strip()
        if not rule_text or rule_text.startswith('#'):
            return None
            
        # Clean up line continuations and normalize
        rule_text = rule_text.replace('\\\n', ' ')
        rule_text = rule_text.replace('\\ ', ' ')
        rule_text = re.sub(r'\s+', ' ', rule_text)
        
        # Extract options first (most reliable part)
        if '(' not in rule_text or ')' not in rule_text:
            return None
            
        # Find the options section
        options_start = rule_text.find('(')
        options_end = rule_text.rfind(')')
        
        if options_start == -1 or options_end == -1 or options_start >= options_end:
            return None
            
        options = rule_text[options_start + 1:options_end]
        header = rule_text[:options_start].strip()
        
        # Extract SID first - it's required
        sid_match = cls.SID_PATTERN.search(options)
        if not sid_match:
            return None
            
        sid = sid_match.group(1)
        
        # Parse header - be flexible
        header_parts = header.split()
        if len(header_parts) < 3:
            return None
            
        action = header_parts[0].lower()
        if action not in ['alert', 'log', 'pass', 'activate', 'dynamic', 'drop', 'reject', 'sdrop']:
            return None
            
        protocol = header_parts[1].lower()
        
        # Extract message
        msg_match = cls.MSG_PATTERN.search(options)
        msg = msg_match.group(1) if msg_match else f"Snort Rule {sid}"
        
        # Extract other metadata
        rev_match = cls.REV_PATTERN.search(options)
        revision = int(rev_match.group(1)) if rev_match else 1
        
        classtype_match = cls.CLASSTYPE_PATTERN.search(options)
        classtype = classtype_match.group(1).strip() if classtype_match else None
        
        priority_match = cls.PRIORITY_PATTERN.search(options)
        priority = int(priority_match.group(1)) if priority_match else 3
        
        # Extract CVE references
        cve_refs = []
        for match in cls.CVE_PATTERN.finditer(options):
            cve_refs.append(f"CVE-{match.group(1)}")
        
        # Also check standard reference format
        for match in cls.REFERENCE_PATTERN.finditer(options):
            ref = match.group(1).strip()
            if ref.startswith('cve,'):
                cve_id = ref.replace('cve,', 'CVE-')
                if cve_id not in cve_refs:
                    cve_refs.append(cve_id)
        
        # Determine severity
        severity = cls._determine_severity(classtype, priority)
        
        # Build metadata
        metadata = {
            'action': action,
            'protocol': protocol,
            'header': header,
            'classtype': classtype,
            'priority': priority,
            'revision': revision,
            'options_raw': options[:500]  # Truncate for storage
        }
        
        # Generate tags
        tags = [protocol]
        if classtype:
            tags.append(classtype.replace('-', '_'))
        if action != 'alert':
            tags.append(f'action_{action}')
        
        return {
            'rule_id': f'snort-{sid}',
            'sid': sid,
            'name': msg,
            'description': msg,
            'rule_content': rule_text[:2000],  # Truncate very long rules
            'rule_type': 'snort',
            'severity': severity,
            'tags': tags,
            'cve_references': cve_refs,
            'metadata': metadata
        }
    
    @classmethod
    def _determine_severity(cls, classtype: Optional[str], priority: int) -> str:
        """Determine severity from classtype and priority"""
        if classtype:
            # Try exact match
            if classtype in cls.CLASSTYPE_SEVERITY:
                return cls.CLASSTYPE_SEVERITY[classtype]
            # Try partial match
            for ct_key, severity in cls.CLASSTYPE_SEVERITY.items():
                if ct_key in classtype or classtype in ct_key:
                    return severity
        
        return cls.SEVERITY_MAP.get(priority, 'medium')


class SnortRuleCollector:
    """Collect and process Snort community rules"""
    
    # Multiple URLs to try
    RULE_URLS = [
        'https://www.snort.org/downloads/community/snort3-community-rules.tar.gz',
        'https://www.snort.org/downloads/community/community-rules.tar.gz',
        'https://www.snort.org/rules/community'
    ]
    
    def __init__(self):
        self.processed_count = 0
        self.valid_count = 0
        self.error_count = 0
        self.parse_failures = 0
        self.rules_by_file = {}
        
    def collect_rules(self) -> Dict[str, Any]:
        """Collect rules from Snort community"""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Download and extract rules
            rules_path = self._download_rules(temp_path)
            
            if not rules_path:
                logger.error("Failed to download rules from any source")
                return self._empty_result()
            
            # Process all .rules files
            collected_rules = self._process_rules_directory(rules_path)
            
            return {
                'source': 'Snort',
                'repository': 'https://www.snort.org/downloads/community',
                'version': 'community',
                'collected_at': datetime.now(timezone.utc).isoformat(),
                'total_rules': self.valid_count,
                'files_processed': len(self.rules_by_file),
                'statistics': {
                    'processed': self.processed_count,
                    'valid': self.valid_count,
                    'errors': self.error_count,
                    'parse_failures': self.parse_failures,
                    'by_file': {k: len(v) for k, v in self.rules_by_file.items()},
                    'unique_sids': len(set(r['sid'] for r in collected_rules)) if collected_rules else 0
                },
                'rules': collected_rules
            }
    
    def _empty_result(self) -> Dict[str, Any]:
        """Return empty result structure"""
        return {
            'source': 'Snort',
            'repository': 'https://www.snort.org/downloads/community',
            'version': 'community',
            'collected_at': datetime.now(timezone.utc).isoformat(),
            'total_rules': 0,
            'files_processed': 0,
            'statistics': {
                'processed': 0,
                'valid': 0,
                'errors': 0,
                'parse_failures': 0
            },
            'rules': []
        }
    
    def _download_rules(self, temp_path: Path) -> Optional[Path]:
        """Download and extract Snort rules tarball"""
        
        for url in self.RULE_URLS:
            try:
                logger.info(f"Attempting to download from {url}")
                
                tar_path = temp_path / 'snort-rules.tar.gz'
                
                # Download with timeout
                req = urllib.request.Request(url, headers={
                    'User-Agent': 'Mozilla/5.0 (compatible; PanoramaCollector/1.0)'
                })
                
                with urllib.request.urlopen(req, timeout=30) as response:
                    with open(tar_path, 'wb') as f:
                        f.write(response.read())
                
                logger.info(f"Downloaded rules, extracting...")
                
                # Extract tarball
                with tarfile.open(tar_path, 'r:gz') as tar:
                    tar.extractall(temp_path)
                
                # Find rules directory
                rules_path = self._find_rules_directory(temp_path)
                
                if rules_path:
                    logger.info(f"Found rules at {rules_path}")
                    return rules_path
                    
            except Exception as e:
                logger.warning(f"Failed to download from {url}: {str(e)}")
                continue
        
        return None
    
    def _find_rules_directory(self, base_path: Path) -> Optional[Path]:
        """Find the directory containing .rules files"""
        
        # Look for .rules files in common locations
        search_patterns = [
            '*.rules',
            '**/rules/*.rules',
            '**/*.rules'
        ]
        
        for pattern in search_patterns:
            rules_files = list(base_path.glob(pattern))
            if rules_files:
                # Return the parent directory of the first rules file
                rules_dir = rules_files[0].parent
                logger.info(f"Found {len(rules_files)} .rules files in {rules_dir}")
                return rules_dir
        
        # Check extracted directories
        for item in base_path.iterdir():
            if item.is_dir():
                # Check this directory
                rules_files = list(item.glob('*.rules'))
                if rules_files:
                    return item
                
                # Check subdirectories
                for subdir in item.iterdir():
                    if subdir.is_dir() and 'rules' in subdir.name.lower():
                        rules_files = list(subdir.glob('*.rules'))
                        if rules_files:
                            return subdir
        
        return None
    
    def _process_rules_directory(self, rules_path: Path) -> List[Dict[str, Any]]:
        """Process all .rules files in directory"""
        all_rules = []
        
        # Find all .rules files
        rules_files = list(rules_path.glob('*.rules'))
        
        if not rules_files:
            # Try subdirectories
            rules_files = list(rules_path.rglob('*.rules'))
        
        logger.info(f"Found {len(rules_files)} .rules files to process")
        
        for rules_file in rules_files:
            if rules_file.name.startswith('.'):
                continue  # Skip hidden files
                
            logger.info(f"Processing {rules_file.name}")
            
            file_rules = self._process_rules_file(rules_file)
            if file_rules:
                all_rules.extend(file_rules)
                self.rules_by_file[rules_file.name] = file_rules
                logger.info(f"Extracted {len(file_rules)} valid rules from {rules_file.name}")
        
        return all_rules
    
    def _process_rules_file(self, rules_file: Path) -> List[Dict[str, Any]]:
        """Process a single .rules file"""
        file_rules = []
        
        try:
            # Try different encodings
            encodings = ['utf-8', 'latin-1', 'cp1252']
            content = None
            
            for encoding in encodings:
                try:
                    with open(rules_file, 'r', encoding=encoding) as f:
                        content = f.read()
                    break
                except UnicodeDecodeError:
                    continue
            
            if not content:
                logger.error(f"Could not read {rules_file.name} with any encoding")
                return []
            
            # Process line by line
            lines = content.split('\n')
            current_rule = ''
            
            for line in lines:
                line = line.strip()
                
                # Skip empty lines and pure comments
                if not line or (line.startswith('#') and not current_rule):
                    continue
                
                # Handle line continuation
                if line.endswith('\\'):
                    current_rule += line[:-1] + ' '
                    continue
                
                # Complete rule line
                if current_rule:
                    line = current_rule + line
                    current_rule = ''
                
                # Skip if it's a comment
                if line.startswith('#'):
                    continue
                
                self.processed_count += 1
                
                try:
                    parsed_rule = SnortRuleParser.parse_rule(line)
                    if parsed_rule:
                        # Add file context
                        parsed_rule['source_file'] = rules_file.name
                        parsed_rule['hash'] = hashlib.sha256(line.encode()).hexdigest()
                        
                        file_rules.append(parsed_rule)
                        self.valid_count += 1
                    else:
                        self.parse_failures += 1
                        if self.parse_failures <= 5:
                            logger.debug(f"Could not parse: {line[:100]}...")
                        
                except Exception as e:
                    logger.debug(f"Error parsing rule: {str(e)[:100]}")
                    self.error_count += 1
            
            logger.info(f"File {rules_file.name}: {len(file_rules)} valid, {self.parse_failures} failed")
        
        except Exception as e:
            logger.error(f"Error processing file {rules_file.name}: {str(e)}")
            self.error_count += 1
            
        return file_rules


def upload_to_s3(rules_data: Dict[str, Any]) -> str:
    """Upload collected rules to S3"""
    
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    
    # Upload main rules file
    data_key = f"{SNORT_PREFIX}/collected/{timestamp}/rules.json"
    
    s3_client.put_object(
        Bucket=STAGING_BUCKET,
        Key=data_key,
        Body=json.dumps(rules_data, default=str),
        ContentType='application/json',
        Metadata={
            'source': 'Snort',
            'rule_count': str(rules_data['total_rules']),
            'timestamp': timestamp,
            'version': rules_data.get('version', 'community')
        }
    )
    
    logger.info(f"Uploaded {rules_data['total_rules']} rules to s3://{STAGING_BUCKET}/{data_key}")
    
    # Upload summary
    summary_key = f"{SNORT_PREFIX}/collected/{timestamp}/summary.json"
    summary = {
        'source': rules_data['source'],
        'timestamp': rules_data['collected_at'],
        'statistics': rules_data['statistics'],
        'data_location': f"s3://{STAGING_BUCKET}/{data_key}"
    }
    
    s3_client.put_object(
        Bucket=STAGING_BUCKET,
        Key=summary_key,
        Body=json.dumps(summary),
        ContentType='application/json'
    )
    
    return data_key


def trigger_processor(s3_key: str, rule_count: int) -> Dict[str, Any]:
    """Trigger the Snort rules processor Lambda"""
    
    payload = {
        'Records': [{
            'eventSource': 'pano-snort-processor',
            's3': {
                'bucket': {
                    'name': STAGING_BUCKET
                },
                'object': {
                    'key': s3_key
                }
            },
            'metadata': {
                'source': 'Snort',
                'rule_count': rule_count
            }
        }]
    }
    
    try:
        response = lambda_client.invoke(
            FunctionName='pano-snort-processor',
            InvocationType='Event',
            Payload=json.dumps(payload)
        )
        
        return {
            'triggered': True,
            'status_code': response['StatusCode'],
            'request_id': response.get('RequestId')
        }
        
    except Exception as e:
        logger.error(f"Failed to trigger processor: {str(e)}")
        return {
            'triggered': False,
            'error': str(e)
        }


def lambda_handler(event, context):
    """Lambda entry point"""
    
    start_time = datetime.now(timezone.utc)
    
    try:
        logger.info("Starting Snort rules collection")
        
        collector = SnortRuleCollector()
        rules_data = collector.collect_rules()
        
        logger.info(f"Collection stats: {json.dumps(rules_data['statistics'])}")
        
        # Upload to S3
        s3_key = upload_to_s3(rules_data)
        
        # Optionally trigger processor
        processor_result = None
        if event.get('trigger_processor', True):
            if rules_data['total_rules'] > 0:
                processor_result = trigger_processor(s3_key, rules_data['total_rules'])
            else:
                logger.warning("No rules to process, skipping processor trigger")
        
        duration = (datetime.now(timezone.utc) - start_time).total_seconds()
        
        result = {
            'statusCode': 200,
            'body': {
                'message': 'Snort rules collection completed',
                'source': 'Snort',
                'rules_collected': rules_data['total_rules'],
                'files_processed': rules_data['files_processed'],
                'statistics': rules_data['statistics'],
                's3_location': f"s3://{STAGING_BUCKET}/{s3_key}",
                'processor_triggered': processor_result is not None,
                'processor_result': processor_result,
                'duration_seconds': duration,
                'timestamp': start_time.isoformat()
            }
        }
        
        logger.info(f"Collection completed: {json.dumps(result['body'])}")
        return result
        
    except Exception as e:
        logger.error(f"Collection failed: {str(e)}", exc_info=True)
        return {
            'statusCode': 500,
            'body': {
                'error': 'Collection failed',
                'message': str(e),
                'timestamp': start_time.isoformat()
            }
        }