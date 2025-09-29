"""
pano-elastic-downloader/lambda_function.py
Downloads Elastic detection rules from GitHub
"""
import json
import logging
import os
import boto3
import tempfile
import hashlib
import urllib.request
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from pathlib import Path

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3_client = boto3.client('s3')
eventbridge_client = boto3.client('events')

STAGING_BUCKET = os.environ.get('STAGING_BUCKET', 'panorama-rulesets')
EVENT_BUS = os.environ.get('EVENT_BUS', 'panorama-rules-processing')
ELASTIC_PREFIX = 'elastic'

class ElasticDownloader:
    """Downloads Elastic detection rules from GitHub"""
    
    GITHUB_API_BASE = 'https://api.github.com'
    REPO = 'elastic/detection-rules'
    RULES_PATH = 'rules'
    
    def __init__(self):
        self.stats = {
            'files_downloaded': 0,
            'total_size': 0,
            'errors': [],
            'rule_types': {}
        }
        self.github_token = os.environ.get('GITHUB_TOKEN')
    
    def download_rules(self) -> Dict[str, Any]:
        """Download and stage Elastic detection rules"""
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Get rule files from GitHub API
            rule_files = self._list_rule_files()
            if not rule_files:
                return self._error_result("Failed to list rule files")
            
            # Download rules
            downloaded_rules = self._download_rule_files(rule_files, temp_path)
            if not downloaded_rules:
                return self._error_result("No rules downloaded")
            
            # Package and upload to S3
            ruleset_id = self._generate_ruleset_id()
            s3_key = self._upload_to_s3(downloaded_rules, ruleset_id)
            
            return {
                'ruleset_id': ruleset_id,
                'source': 'elastic',
                's3_bucket': STAGING_BUCKET,
                's3_key': s3_key,
                'statistics': self.stats,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
    
    def _list_rule_files(self) -> List[Dict[str, Any]]:
        """List all rule files from GitHub API"""
        
        rule_files = []
        headers = {'Accept': 'application/vnd.github.v3+json'}
        
        if self.github_token:
            headers['Authorization'] = f'token {self.github_token}'
        
        # Recursively list all directories under rules/
        dirs_to_process = ['rules']
        
        while dirs_to_process:
            current_path = dirs_to_process.pop(0)
            url = f"{self.GITHUB_API_BASE}/repos/{self.REPO}/contents/{current_path}"
            
            try:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=30) as response:
                    content = json.loads(response.read())
                    
                    for item in content:
                        if item['type'] == 'file' and item['name'].endswith('.toml'):
                            rule_files.append({
                                'path': item['path'],
                                'download_url': item['download_url'],
                                'size': item['size'],
                                'sha': item['sha']
                            })
                            
                            # Track rule type from path
                            rule_type = item['path'].split('/')[1] if '/' in item['path'] else 'unknown'
                            self.stats['rule_types'][rule_type] = self.stats['rule_types'].get(rule_type, 0) + 1
                            
                        elif item['type'] == 'dir':
                            dirs_to_process.append(item['path'])
                            
            except Exception as e:
                logger.warning(f"Failed to list {current_path}: {e}")
                self.stats['errors'].append(f"List failed: {current_path}")
        
        logger.info(f"Found {len(rule_files)} rule files")
        return rule_files
    
    def _download_rule_files(self, rule_files: List[Dict], temp_path: Path) -> List[Dict[str, Any]]:
        """Download individual rule files"""
        
        downloaded_rules = []
        rules_dir = temp_path / 'rules'
        rules_dir.mkdir(exist_ok=True)
        
        for file_info in rule_files[:500]:  # Limit to avoid timeout
            try:
                # Download file content
                req = urllib.request.Request(file_info['download_url'])
                with urllib.request.urlopen(req, timeout=10) as response:
                    content = response.read()
                    
                    # Save to temp directory preserving structure
                    file_path = rules_dir / file_info['path'].replace('/', '_')
                    file_path.write_bytes(content)
                    
                    downloaded_rules.append({
                        'path': file_info['path'],
                        'local_path': str(file_path),
                        'size': len(content),
                        'sha': file_info['sha']
                    })
                    
                    self.stats['files_downloaded'] += 1
                    self.stats['total_size'] += len(content)
                    
            except Exception as e:
                logger.debug(f"Failed to download {file_info['path']}: {e}")
                self.stats['errors'].append(f"Download failed: {file_info['path']}")
        
        logger.info(f"Downloaded {len(downloaded_rules)} rules")
        return downloaded_rules
    
    def _upload_to_s3(self, downloaded_rules: List[Dict], ruleset_id: str) -> str:
        """Upload downloaded rules to S3 as JSON"""
        
        s3_key = f"{ELASTIC_PREFIX}/{ruleset_id}/rules.json"
        
        # Prepare rules data
        rules_data = {
            'source': 'elastic',
            'repository': f"https://github.com/{self.REPO}",
            'ruleset_id': ruleset_id,
            'download_time': datetime.now(timezone.utc).isoformat(),
            'statistics': self.stats,
            'rules': []
        }
        
        # Read and parse each rule file
        for rule_info in downloaded_rules:
            try:
                with open(rule_info['local_path'], 'r') as f:
                    content = f.read()
                    rules_data['rules'].append({
                        'path': rule_info['path'],
                        'content': content,
                        'sha': rule_info['sha']
                    })
            except Exception as e:
                logger.debug(f"Failed to read {rule_info['path']}: {e}")
        
        # Upload to S3
        s3_client.put_object(
            Bucket=STAGING_BUCKET,
            Key=s3_key,
            Body=json.dumps(rules_data),
            ContentType='application/json',
            Metadata={
                'source': 'elastic',
                'ruleset_id': ruleset_id,
                'rule_count': str(len(rules_data['rules']))
            }
        )
        
        logger.info(f"Uploaded to s3://{STAGING_BUCKET}/{s3_key}")
        return s3_key
    
    def _generate_ruleset_id(self) -> str:
        """Generate unique ruleset ID"""
        timestamp = datetime.now(timezone.utc)
        date_str = timestamp.strftime('%Y%m%d')
        time_str = timestamp.strftime('%H%M%S')
        return f"elastic-{date_str}-{time_str}"
    
    def _error_result(self, message: str) -> Dict[str, Any]:
        """Generate error result"""
        return {
            'error': message,
            'source': 'elastic',
            'statistics': self.stats,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }


def lambda_handler(event, context):
    """Lambda handler for Elastic rule downloads"""
    
    try:
        logger.info("Starting Elastic detection rules download")
        
        downloader = ElasticDownloader()
        result = downloader.download_rules()
        
        if 'error' in result:
            logger.error(f"Download failed: {result['error']}")
            return {
                'statusCode': 500,
                'body': json.dumps(result)
            }
        
        # Publish success event to EventBridge
        eventbridge_client.put_events(
            Entries=[{
                'Source': 'rules.downloader.elastic',
                'DetailType': 'com.security.rules.downloaded',
                'Detail': json.dumps(result),
                'EventBusName': EVENT_BUS
            }]
        )
        
        logger.info(f"Successfully downloaded Elastic rules: {result['ruleset_id']}")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Elastic rules downloaded successfully',
                'ruleset_id': result['ruleset_id'],
                'statistics': result['statistics']
            })
        }
        
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        
        # Publish failure event
        eventbridge_client.put_events(
            Entries=[{
                'Source': 'rules.downloader.elastic',
                'DetailType': 'com.security.rules.download.failed',
                'Detail': json.dumps({
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
                'error': 'Download failed',
                'message': str(e)
            })
        }