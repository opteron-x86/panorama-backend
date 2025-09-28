"""
pano-rule-downloader/lambda_function.py
Downloads rulesets and publishes events to EventBridge
"""
import json
import logging
import os
import boto3
import hashlib
import requests
from datetime import datetime, timezone, date
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse
from decimal import Decimal

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3_client = boto3.client('s3')
eventbridge_client = boto3.client('events')

STAGING_BUCKET = os.environ.get('STAGING_BUCKET', 'panorama-rulesets')
EVENT_BUS = os.environ.get('EVENT_BUS', 'default')


class DateTimeEncoder(json.JSONEncoder):
    """JSON encoder that handles datetime objects"""
    def default(self, obj):
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        if isinstance(obj, Decimal):
            return float(obj)
        return super().default(obj)


class RuleDownloader:
    """Generic rule downloader with EventBridge integration"""
    
    RULE_SOURCES = {
        'sigma': {
            'url': 'https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip',
            'type': 'github_archive'
        },
        'snort': {
            'url': 'https://www.snort.org/downloads/community/snortrules-snapshot-3000.tar.gz',
            'type': 'tarball'
        },
        'elastic': {
            'url': 'https://api.github.com/repos/elastic/detection-rules/contents/rules',
            'type': 'github_api'
        }
    }
    
    def __init__(self):
        self.stats = {
            'downloaded': 0,
            'failed': 0,
            'sources': []
        }
    
    def download_rules(self, source: str, url: Optional[str] = None) -> Dict[str, Any]:
        """Download rules from specified source"""
        # Get source configuration
        if source not in self.RULE_SOURCES and not url:
            raise ValueError(f"Unknown source: {source}")
        
        source_config = self.RULE_SOURCES.get(source, {})
        download_url = url or source_config.get('url')
        
        if not download_url:
            raise ValueError(f"No URL provided for source: {source}")
        
        logger.info(f"Downloading {source} rules from {download_url}")
        
        # Generate deterministic ruleset ID
        ruleset_id = self._generate_ruleset_id(source, download_url)
        
        try:
            # Download content
            response = requests.get(download_url, timeout=60)
            response.raise_for_status()
            
            # Process based on type
            if source == 'sigma':
                rules_data = self._process_sigma_download(response.content)
            elif source == 'snort':
                rules_data = self._process_snort_download(response.content)
            elif source == 'elastic':
                rules_data = self._process_elastic_download(response.json())
            else:
                # Generic processing
                rules_data = {
                    'source': source,
                    'content': response.text if response.headers.get('content-type', '').startswith('text/') else None,
                    'raw_size': len(response.content)
                }
            
            # Add metadata
            rules_data.update({
                'ruleset_id': ruleset_id,
                'source': source,
                'download_url': download_url,
                'downloaded_at': datetime.now(timezone.utc).isoformat(),
                'total_rules': rules_data.get('total_rules', 0)
            })
            
            # Store in S3
            s3_key = self._upload_to_s3(rules_data, source, ruleset_id)
            
            self.stats['downloaded'] += 1
            self.stats['sources'].append(source)
            
            return {
                'ruleset_id': ruleset_id,
                'source': source,
                's3_bucket': STAGING_BUCKET,
                's3_key': s3_key,
                'rule_count': rules_data.get('total_rules', 0)
            }
            
        except Exception as e:
            logger.error(f"Failed to download {source} rules: {e}")
            self.stats['failed'] += 1
            raise
    
    def _process_sigma_download(self, content: bytes) -> Dict[str, Any]:
        """Process Sigma GitHub archive"""
        import zipfile
        import io
        import yaml
        
        rules = {}
        total = 0
        
        with zipfile.ZipFile(io.BytesIO(content)) as zf:
            for file_info in zf.filelist:
                if file_info.filename.endswith('.yml'):
                    try:
                        content = zf.read(file_info.filename)
                        rule = yaml.safe_load(content)
                        
                        if rule and 'detection' in rule:
                            # Extract category from path
                            parts = file_info.filename.split('/')
                            category = parts[-2] if len(parts) > 1 else 'uncategorized'
                            
                            if category not in rules:
                                rules[category] = []
                            
                            # Add file path to rule
                            rule['file_path'] = file_info.filename
                            rule['content_hash'] = hashlib.sha256(content).hexdigest()[:16]
                            rule['rule_id'] = rule.get('id', hashlib.md5(content).hexdigest())
                            
                            # Normalize fields
                            rule['name'] = rule.get('title', 'Untitled')
                            rule['severity'] = rule.get('level', 'medium')
                            rule['tags'] = rule.get('tags', [])
                            rule['status'] = rule.get('status', 'experimental')
                            rule['author'] = rule.get('author', '')
                            rule['falsepositives'] = rule.get('falsepositives', [])
                            rule['references'] = rule.get('references', [])
                            rule['mitre_techniques'] = self._extract_mitre_from_tags(rule.get('tags', []))
                            
                            # Convert dates to strings
                            if 'date' in rule and rule['date']:
                                rule['date'] = str(rule['date'])
                            if 'modified' in rule and rule['modified']:
                                rule['modified'] = str(rule['modified'])
                            rules[category].append(rule)
                            total += 1
                    except Exception as e:
                        logger.debug(f"Skipped file {file_info.filename}: {e}")
        
        return {
            'rules': rules,
            'total_rules': total,
            'categories': list(rules.keys()),
            'statistics': {
                'by_category': {cat: len(rules[cat]) for cat in rules},
                'total': total
            }
        }
    
    def _process_snort_download(self, content: bytes) -> Dict[str, Any]:
        """Process Snort tarball"""
        import tarfile
        import io
        
        rules = []
        total = 0
        
        with tarfile.open(fileobj=io.BytesIO(content)) as tf:
            for member in tf.getmembers():
                if member.name.endswith('.rules'):
                    try:
                        content = tf.extractfile(member).read().decode('utf-8')
                        lines = content.split('\n')
                        
                        for line in lines:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                # Parse basic Snort rule structure
                                rule = self._parse_snort_rule(line)
                                if rule:
                                    rules.append(rule)
                                    total += 1
                    except Exception as e:
                        logger.debug(f"Failed to parse {member.name}: {e}")
        
        return {
            'rules': {'all': rules},
            'total_rules': total,
            'statistics': {'total': total}
        }
    
    def _process_elastic_download(self, files: List[Dict]) -> Dict[str, Any]:
        """Process Elastic rules from GitHub API"""
        rules = []
        total = 0
        
        for file_info in files:
            if file_info['name'].endswith('.toml'):
                try:
                    # Would need to fetch individual file content
                    # This is simplified for the example
                    total += 1
                except Exception as e:
                    logger.debug(f"Failed to process {file_info['name']}: {e}")
        
        return {
            'rules': {'elastic': rules},
            'total_rules': total,
            'statistics': {'total': total}
        }
    
    def _parse_snort_rule(self, rule_line: str) -> Optional[Dict[str, Any]]:
        """Basic Snort rule parser"""
        import re
        
        # Simplified Snort rule parsing
        match = re.match(r'(\w+)\s+(\S+)\s+(\S+)\s+->\s+(\S+)\s+(\S+)\s+\((.*)\)', rule_line)
        if match:
            action, proto, src_ip, dst_ip, dst_port, options = match.groups()
            
            # Extract msg and sid from options
            msg_match = re.search(r'msg:"([^"]+)"', options)
            sid_match = re.search(r'sid:(\d+)', options)
            
            return {
                'rule_id': sid_match.group(1) if sid_match else hashlib.md5(rule_line.encode()).hexdigest()[:16],
                'name': msg_match.group(1) if msg_match else 'Snort Rule',
                'action': action,
                'protocol': proto,
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'destination_port': dst_port,
                'options': options,
                'rule_content': rule_line
            }
        return None
    
    def _extract_mitre_from_tags(self, tags: List[str]) -> List[str]:
        """Extract MITRE techniques from tags"""
        techniques = []
        for tag in tags:
            if isinstance(tag, str) and tag.startswith('attack.'):
                technique = tag.replace('attack.', '').upper()
                if technique.startswith('T'):
                    techniques.append(technique)
        return techniques
    
    def _generate_ruleset_id(self, source: str, url: str) -> str:
        """Generate unique ruleset ID"""
        timestamp = datetime.now(timezone.utc).isoformat()
        unique = f"{source}:{url}:{timestamp}"
        return hashlib.sha256(unique.encode()).hexdigest()[:16]
    
    def _upload_to_s3(self, rules_data: Dict, source: str, ruleset_id: str) -> str:
        """Upload rules to S3"""
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        s3_key = f"rulesets/{source}/{timestamp}_{ruleset_id}.json"
        
        s3_client.put_object(
            Bucket=STAGING_BUCKET,
            Key=s3_key,
            Body=json.dumps(rules_data, cls=DateTimeEncoder),
            ContentType='application/json',
            Metadata={
                'source': source,
                'ruleset_id': ruleset_id,
                'rule_count': str(rules_data.get('total_rules', 0))
            }
        )
        
        logger.info(f"Uploaded {rules_data.get('total_rules', 0)} rules to s3://{STAGING_BUCKET}/{s3_key}")
        return s3_key


def publish_event(detail: Dict[str, Any], event_type: str = 'downloaded'):
    """Publish event to EventBridge"""
    try:
        eventbridge_client.put_events(
            Entries=[{
                'Source': 'rules.downloader',
                'DetailType': f'com.security.rules.{event_type}',
                'Detail': json.dumps(detail, cls=DateTimeEncoder),
                'EventBusName': EVENT_BUS
            }]
        )
        logger.info(f"Published {event_type} event for {detail.get('source')}")
    except Exception as e:
        logger.error(f"Failed to publish event: {e}")
        raise


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda entry point"""
    start_time = datetime.now(timezone.utc)
    
    try:
        # Get parameters
        source = event.get('source', 'sigma')
        url = event.get('url')
        sources = event.get('sources', [source])
        
        downloader = RuleDownloader()
        results = []
        
        # Process each source
        for src in sources:
            try:
                # Download rules
                result = downloader.download_rules(src, url if src == source else None)
                results.append(result)
                
                # Publish event to EventBridge
                event_detail = {
                    'ruleset_id': result['ruleset_id'],
                    'source': result['source'],
                    's3_bucket': result['s3_bucket'],
                    's3_key': result['s3_key'],
                    'rule_count': result['rule_count'],
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }
                
                publish_event(event_detail)
                
            except Exception as e:
                logger.error(f"Failed to process {src}: {e}")
                
                # Publish failure event
                publish_event({
                    'source': src,
                    'error': str(e),
                    'failure_type': 'download_failed',
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }, 'failed')
        
        duration = (datetime.now(timezone.utc) - start_time).total_seconds()
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Rule download completed',
                'results': results,
                'statistics': downloader.stats,
                'duration_seconds': duration
            }, cls=DateTimeEncoder)
        }
        
    except Exception as e:
        logger.error(f"Processing failed: {e}", exc_info=True)
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': 'Processing failed',
                'message': str(e)
            }, cls=DateTimeEncoder)
        }