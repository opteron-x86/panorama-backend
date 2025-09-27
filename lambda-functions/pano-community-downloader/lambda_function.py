"""
Sigma Rules Collector Lambda - Managed by Terraform
"""
import json
import logging
import os
import boto3
import tempfile
import hashlib
import yaml
import zipfile
import urllib.request
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from pathlib import Path

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3_client = boto3.client('s3')
lambda_client = boto3.client('lambda')

STAGING_BUCKET = os.environ.get('STAGING_BUCKET', 'panorama-rulesets-538269499906')
SIGMA_PREFIX = 'sigma'


class SigmaRuleCollector:
    
    REPO_ZIP_URL = 'https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip'
    
    SEVERITY_NORMALIZATION = {
        'informational': 'info',
        'low': 'low',
        'medium': 'medium',
        'high': 'high',
        'critical': 'critical'
    }
    
    def __init__(self):
        self.processed_count = 0
        self.valid_count = 0
        self.error_count = 0
        self.rules_by_category = {}
        
    def collect_rules(self) -> Dict[str, Any]:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Download and extract repository
            repo_path = self._download_repository(temp_path)
            
            # Process rules directory
            rules_path = repo_path / 'rules'
            if not rules_path.exists():
                raise FileNotFoundError(f"Rules directory not found at {rules_path}")
            
            collected_rules = self._process_rules_directory(rules_path)
            
            return {
                'source': 'Sigma',
                'repository': 'https://github.com/SigmaHQ/sigma',
                'branch': 'master',
                'collected_at': datetime.now(timezone.utc).isoformat(),
                'total_rules': self.valid_count,
                'categories': list(self.rules_by_category.keys()),
                'statistics': {
                    'processed': self.processed_count,
                    'valid': self.valid_count,
                    'errors': self.error_count,
                    'by_category': {k: len(v) for k, v in self.rules_by_category.items()}
                },
                'rules': collected_rules
            }
    
    def _download_repository(self, temp_path: Path) -> Path:
        """Download repository as zip and extract"""
        zip_path = temp_path / 'sigma.zip'
        
        logger.info(f"Downloading Sigma repository from {self.REPO_ZIP_URL}")
        
        # Download zip file
        with urllib.request.urlopen(self.REPO_ZIP_URL) as response:
            with open(zip_path, 'wb') as f:
                f.write(response.read())
        
        logger.info(f"Downloaded repository, extracting to {temp_path}")
        
        # Extract zip
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(temp_path)
        
        # Find extracted directory (GitHub adds -master suffix)
        extracted_dirs = [d for d in temp_path.iterdir() if d.is_dir() and d.name.startswith('sigma')]
        if not extracted_dirs:
            raise RuntimeError("Failed to find extracted repository directory")
        
        repo_path = extracted_dirs[0]
        logger.info(f"Repository extracted to {repo_path}")
        
        return repo_path
    
    def _process_rules_directory(self, rules_path: Path) -> List[Dict[str, Any]]:
        all_rules = []
        
        for yaml_file in rules_path.rglob('*.yml'):
            # Skip test files and deprecated rules
            relative_path = yaml_file.relative_to(rules_path)
            path_str = str(relative_path).lower()
            if any(skip in path_str for skip in ['test', 'deprecated', 'unsupported']):
                continue
            
            rule_data = self._process_rule_file(yaml_file, rules_path)
            if rule_data:
                all_rules.append(rule_data)
                
                # Track by category
                category = str(relative_path.parts[0]) if relative_path.parts else 'uncategorized'
                if category not in self.rules_by_category:
                    self.rules_by_category[category] = []
                self.rules_by_category[category].append(rule_data['rule_id'])
        
        return all_rules
    
    def _process_rule_file(self, file_path: Path, base_path: Path) -> Optional[Dict[str, Any]]:
        self.processed_count += 1
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse YAML
            rule = yaml.safe_load(content)
            
            if not self._validate_sigma_rule(rule):
                return None
            
            # Generate unique ID
            content_hash = hashlib.sha256(content.encode()).hexdigest()
            rule_id = f"sigma_{content_hash[:16]}"
            
            # Extract metadata
            relative_path = file_path.relative_to(base_path)
            
            # Extract MITRE techniques
            mitre_techniques = self._extract_mitre_techniques(rule.get('tags', []))
            
            # Extract data sources
            data_sources = self._extract_data_sources(rule.get('logsource', {}))
            
            # Build structured rule data
            rule_data = {
                'rule_id': rule_id,
                'file_path': str(relative_path),
                'content_hash': content_hash,
                'name': rule.get('title', 'Untitled'),
                'description': rule.get('description', ''),
                'status': rule.get('status', 'experimental'),
                'author': rule.get('author', ''),
                'date': str(rule.get('date', '')),
                'modified': str(rule.get('modified', '')),
                'severity': self.SEVERITY_NORMALIZATION.get(rule.get('level', 'medium'), 'medium'),
                'tags': rule.get('tags', []),
                'mitre_techniques': mitre_techniques,
                'data_sources': data_sources,
                'logsource': rule.get('logsource', {}),
                'detection': rule.get('detection', {}),
                'falsepositives': rule.get('falsepositives', []),
                'references': rule.get('references', []),
                'raw_content': content
            }
            
            self.valid_count += 1
            return rule_data
            
        except yaml.YAMLError as e:
            logger.warning(f"YAML parse error in {file_path}: {str(e)}")
            self.error_count += 1
            return None
        except Exception as e:
            logger.warning(f"Failed to process {file_path}: {str(e)}")
            self.error_count += 1
            return None
    
    def _validate_sigma_rule(self, rule: Dict[str, Any]) -> bool:
        """Validate required Sigma rule fields"""
        if not isinstance(rule, dict):
            return False
        required_fields = ['title', 'detection']
        return all(field in rule for field in required_fields)
    
    def _extract_mitre_techniques(self, tags: List[str]) -> List[str]:
        techniques = []
        for tag in tags:
            if tag.startswith('attack.t'):
                technique = tag.replace('attack.', '').upper()
                if technique.startswith('T') and technique[1:].split('.')[0].isdigit():
                    techniques.append(technique)
        return techniques
    
    def _extract_data_sources(self, logsource: Dict[str, Any]) -> List[str]:
        sources = []
        
        if 'product' in logsource:
            sources.append(f"product:{logsource['product']}")
        if 'service' in logsource:
            sources.append(f"service:{logsource['service']}")
        if 'category' in logsource:
            sources.append(f"category:{logsource['category']}")
            
        return sources if sources else ['unknown']


def upload_to_s3(rules_data: Dict[str, Any]) -> str:
    """Upload collected rules to S3"""
    
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    
    # Upload main rules file
    data_key = f"{SIGMA_PREFIX}/collected/{timestamp}/rules.json"
    
    s3_client.put_object(
        Bucket=STAGING_BUCKET,
        Key=data_key,
        Body=json.dumps(rules_data, default=str),
        ContentType='application/json',
        Metadata={
            'source': 'Sigma',
            'rule_count': str(rules_data['total_rules']),
            'timestamp': timestamp,
            'categories': ','.join(rules_data['categories'][:10])
        }
    )
    
    logger.info(f"Uploaded {rules_data['total_rules']} rules to s3://{STAGING_BUCKET}/{data_key}")
    
    # Upload summary
    summary_key = f"{SIGMA_PREFIX}/collected/{timestamp}/summary.json"
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
    """Trigger the rules importer Lambda"""
    
    payload = {
        'Records': [{
            'eventSource': 'pano-sigma-processor',
            's3': {
                'bucket': {
                    'name': STAGING_BUCKET
                },
                'object': {
                    'key': s3_key
                }
            },
            'metadata': {
                'source': 'Sigma',
                'rule_count': rule_count
            }
        }]
    }
    
    try:
        response = lambda_client.invoke(
            FunctionName='pano-sigma-processor',
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
        collector = SigmaRuleCollector()
        
        logger.info("Starting Sigma rules collection")
        rules_data = collector.collect_rules()
        
        # Upload to S3
        s3_key = upload_to_s3(rules_data)
        
        # Optionally trigger processor
        processor_result = None
        if event.get('trigger_processor', True):
            processor_result = trigger_processor(s3_key, rules_data['total_rules'])
        
        duration = (datetime.now(timezone.utc) - start_time).total_seconds()
        
        result = {
            'statusCode': 200,
            'body': {
                'message': 'Sigma rules collection completed',
                'source': 'Sigma',
                'rules_collected': rules_data['total_rules'],
                'categories': len(rules_data['categories']),
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
        logger.error(f"Collection failed: {str(e)}")
        return {
            'statusCode': 500,
            'body': {
                'error': 'Collection failed',
                'message': str(e),
                'timestamp': start_time.isoformat()
            }
        }