"""
pano-sigma-downloader/lambda_function.py
Downloads Sigma rules from GitHub and stages them for parsing
"""
import json
import logging
import os
import boto3
import tempfile
import hashlib
import zipfile
import urllib.request
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from pathlib import Path

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3_client = boto3.client('s3')
eventbridge_client = boto3.client('events')

STAGING_BUCKET = os.environ.get('STAGING_BUCKET', 'panorama-rulesets')
EVENT_BUS = os.environ.get('EVENT_BUS', 'panorama-rules-processing')
SIGMA_PREFIX = 'sigma'

class SigmaDownloader:
    """Downloads Sigma rules from GitHub repository"""
    
    SIGMA_URLS = [
        'https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip',
        'https://github.com/SigmaHQ/sigma/archive/master.zip'  # Fallback
    ]
    
    RULE_DIRECTORIES = [
        'rules',
        'rules-emerging-threats',
        'rules-threat-hunting'
    ]
    
    def __init__(self):
        self.stats = {
            'files_downloaded': 0,
            'total_size': 0,
            'directories_processed': [],
            'errors': []
        }
    
    def download_rules(self) -> Dict[str, Any]:
        """Download and stage Sigma rules"""
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Download repository
            zip_path = self._download_repository(temp_path)
            if not zip_path:
                return self._error_result("Failed to download Sigma repository")
            
            # Extract and collect rules
            rules_collected = self._extract_and_collect_rules(zip_path, temp_path)
            if not rules_collected:
                return self._error_result("No rules found in repository")
            
            # Stage to S3
            ruleset_id = self._generate_ruleset_id()
            s3_key = self._upload_to_s3(rules_collected, ruleset_id)
            
            return {
                'ruleset_id': ruleset_id,
                'source': 'sigma',
                's3_bucket': STAGING_BUCKET,
                's3_key': s3_key,
                'statistics': self.stats,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
    
    def _download_repository(self, temp_path: Path) -> Optional[Path]:
        """Download Sigma repository from GitHub"""
        
        for url in self.SIGMA_URLS:
            try:
                logger.info(f"Downloading Sigma repository from {url}")
                zip_path = temp_path / 'sigma-master.zip'
                
                req = urllib.request.Request(url, headers={
                    'User-Agent': 'Mozilla/5.0 (PanoramaCollector/1.0)',
                    'Accept': 'application/zip'
                })
                
                with urllib.request.urlopen(req, timeout=60) as response:
                    content = response.read()
                    zip_path.write_bytes(content)
                    self.stats['total_size'] = len(content)
                
                logger.info(f"Downloaded {len(content) / (1024*1024):.2f} MB")
                return zip_path
                
            except Exception as e:
                logger.warning(f"Failed to download from {url}: {e}")
                self.stats['errors'].append(f"Download failed: {str(e)}")
                continue
        
        return None
    
    def _extract_and_collect_rules(self, zip_path: Path, temp_path: Path) -> Dict[str, List[Path]]:
        """Extract rules from downloaded zip file"""
        
        rules_by_category = {}
        extract_path = temp_path / 'extracted'
        extract_path.mkdir(exist_ok=True)
        
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                # Extract everything
                zip_ref.extractall(extract_path)
                
                # Find the root directory (usually sigma-master)
                root_dirs = list(extract_path.iterdir())
                if not root_dirs:
                    return {}
                
                sigma_root = root_dirs[0]
                
                # Collect rules from each directory
                for rule_dir in self.RULE_DIRECTORIES:
                    rules_path = sigma_root / rule_dir
                    if not rules_path.exists():
                        logger.info(f"Directory {rule_dir} not found, skipping")
                        continue
                    
                    category_rules = self._collect_yaml_files(rules_path, rule_dir)
                    if category_rules:
                        rules_by_category[rule_dir] = category_rules
                        self.stats['directories_processed'].append(rule_dir)
                        logger.info(f"Collected {len(category_rules)} rules from {rule_dir}")
                
        except Exception as e:
            logger.error(f"Failed to extract rules: {e}")
            self.stats['errors'].append(f"Extraction failed: {str(e)}")
            return {}
        
        return rules_by_category
    
    def _collect_yaml_files(self, rules_path: Path, category: str) -> List[Path]:
        """Recursively collect all YAML rule files"""
        
        yaml_files = []
        
        for yaml_file in rules_path.rglob('*.yml'):
            # Skip test files and deprecated rules
            if any(skip in str(yaml_file) for skip in ['test/', 'deprecated/', '.github/']):
                continue
            
            yaml_files.append(yaml_file)
            self.stats['files_downloaded'] += 1
        
        # Also check .yaml extension
        for yaml_file in rules_path.rglob('*.yaml'):
            if any(skip in str(yaml_file) for skip in ['test/', 'deprecated/', '.github/']):
                continue
            
            yaml_files.append(yaml_file)
            self.stats['files_downloaded'] += 1
        
        return yaml_files
    
    def _upload_to_s3(self, rules_collected: Dict[str, List[Path]], ruleset_id: str) -> str:
        """Upload collected rules to S3 as structured JSON"""
        
        s3_key = f"{SIGMA_PREFIX}/{ruleset_id}/rules.json"
        
        # Prepare rules data
        rules_data = {
            'source': 'sigma',
            'repository': 'https://github.com/SigmaHQ/sigma',
            'ruleset_id': ruleset_id,
            'download_time': datetime.now(timezone.utc).isoformat(),
            'statistics': self.stats,
            'categories': {}
        }
        
        # Process each category
        for category, rule_files in rules_collected.items():
            category_rules = []
            
            for rule_file in rule_files:
                try:
                    # Read rule content
                    content = rule_file.read_text(encoding='utf-8', errors='ignore')
                    
                    # Store rule with metadata
                    relative_path = str(rule_file).split('sigma-master/')[-1] if 'sigma-master/' in str(rule_file) else rule_file.name
                    
                    category_rules.append({
                        'path': relative_path,
                        'filename': rule_file.name,
                        'content': content,
                        'size': len(content),
                        'sha256': hashlib.sha256(content.encode()).hexdigest()
                    })
                    
                except Exception as e:
                    logger.debug(f"Failed to read {rule_file}: {e}")
                    self.stats['errors'].append(f"Read failed: {rule_file.name}")
            
            if category_rules:
                rules_data['categories'][category] = {
                    'count': len(category_rules),
                    'rules': category_rules
                }
        
        # Upload to S3
        s3_client.put_object(
            Bucket=STAGING_BUCKET,
            Key=s3_key,
            Body=json.dumps(rules_data),
            ContentType='application/json',
            Metadata={
                'source': 'sigma',
                'ruleset_id': ruleset_id,
                'rule_count': str(self.stats['files_downloaded']),
                'categories': ','.join(self.stats['directories_processed'])
            }
        )
        
        logger.info(f"Uploaded to s3://{STAGING_BUCKET}/{s3_key}")
        return s3_key
    
    def _generate_ruleset_id(self) -> str:
        """Generate unique ruleset ID"""
        timestamp = datetime.now(timezone.utc)
        date_str = timestamp.strftime('%Y%m%d')
        time_str = timestamp.strftime('%H%M%S')
        return f"sigma-{date_str}-{time_str}"
    
    def _error_result(self, message: str) -> Dict[str, Any]:
        """Generate error result"""
        return {
            'error': message,
            'source': 'sigma',
            'statistics': self.stats,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }


def lambda_handler(event, context):
    """Lambda handler for Sigma rule downloads"""
    
    try:
        logger.info("Starting Sigma rule download")
        
        downloader = SigmaDownloader()
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
                'Source': 'rules.downloader.sigma',
                'DetailType': 'com.security.rules.downloaded',
                'Detail': json.dumps(result),
                'EventBusName': EVENT_BUS
            }]
        )
        
        logger.info(f"Successfully downloaded Sigma rules: {result['ruleset_id']}")
        logger.info(f"Statistics: {result['statistics']}")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Sigma rules downloaded successfully',
                'ruleset_id': result['ruleset_id'],
                'statistics': result['statistics']
            })
        }
        
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        
        # Publish failure event
        eventbridge_client.put_events(
            Entries=[{
                'Source': 'rules.downloader.sigma',
                'DetailType': 'com.security.rules.download.failed',
                'Detail': json.dumps({
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
                'error': 'Download failed',
                'message': str(e)
            })
        }