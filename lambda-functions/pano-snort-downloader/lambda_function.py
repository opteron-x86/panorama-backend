"""
pano-snort-downloader/lambda_function.py
Downloads Snort community rules and stages them for parsing
"""
import json
import logging
import os
import boto3
import tempfile
import hashlib
import tarfile
import urllib.request
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from pathlib import Path

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3_client = boto3.client('s3')
eventbridge_client = boto3.client('events')

STAGING_BUCKET = os.environ.get('STAGING_BUCKET', 'panorama-rulesets')
EVENT_BUS = os.environ.get('EVENT_BUS', 'panorama-rules-processing')
SNORT_PREFIX = 'snort'

class SnortDownloader:
    """Downloads Snort community rules"""
    
    RULE_URLS = [
        'https://www.snort.org/downloads/community/snort3-community-rules.tar.gz',  # Primary - most comprehensive
        'https://www.snort.org/downloads/community/community-rules.tar.gz',         # Fallback
        'https://www.snort.org/downloads/community/snortrules-snapshot-3000.tar.gz' # Last resort
    ]
    
    def __init__(self):
        self.stats = {
            'files_downloaded': 0,
            'total_size': 0,
            'errors': []
        }
    
    def download_rules(self) -> Dict[str, Any]:
        """Download and stage Snort rules"""
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Download rules
            tar_path = self._download_tarball(temp_path)
            if not tar_path:
                return self._error_result("Failed to download rules")
            
            # Extract and stage
            extracted_path = self._extract_rules(tar_path, temp_path)
            if not extracted_path:
                return self._error_result("Failed to extract rules")
            
            # Upload to S3
            ruleset_id = self._generate_ruleset_id()
            s3_key = self._upload_to_s3(extracted_path, ruleset_id)
            
            return {
                'ruleset_id': ruleset_id,
                'source': 'snort',
                's3_bucket': STAGING_BUCKET,
                's3_key': s3_key,
                'statistics': self.stats,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
    
    def _download_tarball(self, temp_path: Path) -> Optional[Path]:
        """Download Snort rules tarball"""
        
        for url in self.RULE_URLS:
            try:
                logger.info(f"Attempting download from {url}")
                tar_path = temp_path / 'snort-rules.tar.gz'
                
                req = urllib.request.Request(url, headers={
                    'User-Agent': 'Mozilla/5.0 (PanoramaCollector/1.0)'
                })
                
                with urllib.request.urlopen(req, timeout=30) as response:
                    content = response.read()
                    tar_path.write_bytes(content)
                    self.stats['total_size'] = len(content)
                
                logger.info(f"Downloaded {len(content)} bytes")
                return tar_path
                
            except Exception as e:
                logger.warning(f"Failed to download from {url}: {e}")
                self.stats['errors'].append(str(e))
                continue
        
        return None
    
    def _extract_rules(self, tar_path: Path, temp_path: Path) -> Optional[Path]:
        """Extract rules from tarball"""
        
        try:
            extract_path = temp_path / 'extracted'
            extract_path.mkdir(exist_ok=True)
            
            with tarfile.open(tar_path, 'r:gz') as tar:
                # Extract only .rules files
                rules_members = [m for m in tar.getmembers() 
                               if m.name.endswith('.rules')]
                
                for member in rules_members:
                    tar.extract(member, extract_path)
                    self.stats['files_downloaded'] += 1
                
                logger.info(f"Extracted {len(rules_members)} rule files")
            
            return extract_path
            
        except Exception as e:
            logger.error(f"Failed to extract rules: {e}")
            self.stats['errors'].append(str(e))
            return None
    
    def _upload_to_s3(self, extracted_path: Path, ruleset_id: str) -> str:
        """Upload extracted rules to S3"""
        
        s3_key = f"{SNORT_PREFIX}/{ruleset_id}/rules.tar.gz"
        
        # Create new tarball with just the rules
        tar_path = extracted_path.parent / 'snort-rules-staged.tar.gz'
        
        with tarfile.open(tar_path, 'w:gz') as tar:
            for rules_file in extracted_path.rglob('*.rules'):
                tar.add(rules_file, arcname=rules_file.name)
        
        # Upload to S3
        s3_client.upload_file(
            str(tar_path), 
            STAGING_BUCKET,
            s3_key,
            ExtraArgs={
                'Metadata': {
                    'source': 'snort',
                    'ruleset_id': ruleset_id,
                    'download_time': datetime.now(timezone.utc).isoformat()
                }
            }
        )
        
        logger.info(f"Uploaded to s3://{STAGING_BUCKET}/{s3_key}")
        return s3_key
    
    def _generate_ruleset_id(self) -> str:
        """Generate unique ruleset ID"""
        timestamp = datetime.now(timezone.utc)
        date_str = timestamp.strftime('%Y%m%d')
        time_str = timestamp.strftime('%H%M%S')
        return f"snort-{date_str}-{time_str}"
    
    def _error_result(self, message: str) -> Dict[str, Any]:
        """Generate error result"""
        return {
            'error': message,
            'source': 'snort',
            'statistics': self.stats,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }


def lambda_handler(event, context):
    """Lambda handler for Snort rule downloads"""
    
    try:
        logger.info(f"Starting Snort rule download")
        
        downloader = SnortDownloader()
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
                'Source': 'rules.downloader.snort',
                'DetailType': 'com.security.rules.downloaded',
                'Detail': json.dumps(result),
                'EventBusName': EVENT_BUS
            }]
        )
        
        logger.info(f"Successfully downloaded Snort rules: {result['ruleset_id']}")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Snort rules downloaded successfully',
                'ruleset_id': result['ruleset_id'],
                'statistics': result['statistics']
            })
        }
        
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        
        # Publish failure event
        eventbridge_client.put_events(
            Entries=[{
                'Source': 'rules.downloader.snort',
                'DetailType': 'com.security.rules.download.failed',
                'Detail': json.dumps({
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
                'error': 'Download failed',
                'message': str(e)
            })
        }