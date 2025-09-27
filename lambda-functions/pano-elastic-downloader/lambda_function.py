"""
Elastic Detection Rules Downloader Lambda
Downloads rules from elastic/detection-rules GitHub repository
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
from typing import Dict, List, Any, Optional
from pathlib import Path
import toml
import re

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3_client = boto3.client('s3')
lambda_client = boto3.client('lambda')

STAGING_BUCKET = os.environ.get('STAGING_BUCKET', 'panorama-rulesets-538269499906')
ELASTIC_PREFIX = 'elastic'
GITHUB_API_TOKEN = os.environ.get('GITHUB_TOKEN', '')  # Optional, for rate limiting

class ElasticRuleDownloader:
    """Download and parse Elastic detection rules"""
    
    def __init__(self):
        self.stats = {
            'total_files': 0,
            'rules_parsed': 0,
            'parse_errors': 0,
            'manual_extractions': 0,
            'skipped_deprecated': 0,
            'categories': set()
        }
        
    def download_rules(self) -> str:
        """Download latest Elastic detection rules release"""
        # Use GitHub API to get latest release
        api_url = "https://api.github.com/repos/elastic/detection-rules/releases/latest"
        
        headers = {'Accept': 'application/vnd.github.v3+json'}
        if GITHUB_API_TOKEN:
            headers['Authorization'] = f'token {GITHUB_API_TOKEN}'
            
        req = urllib.request.Request(api_url, headers=headers)
        
        try:
            with urllib.request.urlopen(req) as response:
                release_data = json.loads(response.read())
                
            # Get zipball URL
            zipball_url = release_data['zipball_url']
            version = release_data['tag_name']
            
            logger.info(f"Downloading Elastic rules version: {version}")
            
        except Exception as e:
            # Fallback to main branch if releases API fails
            logger.warning(f"Failed to get latest release: {e}, using main branch")
            zipball_url = "https://github.com/elastic/detection-rules/archive/refs/heads/main.zip"
            version = "main"
        
        # Download the archive
        with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as tmp_file:
            req = urllib.request.Request(zipball_url, headers=headers)
            with urllib.request.urlopen(req) as response:
                tmp_file.write(response.read())
            return tmp_file.name, version
    
    def _preprocess_toml_content(self, content: str) -> str:
        """Preprocess TOML content to handle edge cases"""
        lines = content.split('\n')
        processed_lines = []
        in_multiline = False
        multiline_delim = None
        
        for i, line in enumerate(lines):
            # Check for multiline string delimiters
            if '"""' in line or "'''" in line:
                if '"""' in line:
                    count = line.count('"""')
                    if count % 2 == 1:  # Odd number means state change
                        in_multiline = not in_multiline
                        multiline_delim = '"""'
                elif "'''" in line:
                    count = line.count("'''")
                    if count % 2 == 1:
                        in_multiline = not in_multiline
                        multiline_delim = "'''"
            
            processed_lines.append(line)
        
        return '\n'.join(processed_lines)
    
    def parse_rule_file(self, content: str, file_path: str) -> Optional[Dict[str, Any]]:
        """Parse a single TOML rule file with error recovery"""
        try:
            # Skip deprecated rules
            if '_deprecated' in file_path:
                logger.debug(f"Skipping deprecated rule: {file_path}")
                self.stats['skipped_deprecated'] += 1
                return None
                
            # Try standard parsing first
            try:
                rule_data = toml.loads(content)
            except toml.TomlDecodeError as e:
                # If standard parsing fails, try with preprocessing
                logger.debug(f"Standard parsing failed for {file_path}, trying preprocessing: {e}")
                content = self._preprocess_toml_content(content)
                
                # Try parsing again, if it still fails, try to extract key fields manually
                try:
                    rule_data = toml.loads(content)
                except toml.TomlDecodeError:
                    # Extract critical fields manually as fallback
                    logger.warning(f"TOML parsing failed for {file_path}, extracting fields manually")
                    rule_data = self._manual_field_extraction(content, file_path)
                    if rule_data:
                        self.stats['manual_extractions'] += 1
                    else:
                        return None
            
            if 'rule' not in rule_data:
                return None
                
            rule = rule_data['rule']
            metadata = rule_data.get('metadata', {})
            
            # Extract core fields
            parsed = {
                'rule_id': rule.get('rule_id', ''),
                'name': rule.get('name', ''),
                'description': rule.get('description', ''),
                'author': rule.get('author', []),
                'license': rule.get('license', 'Elastic License v2'),
                'risk_score': rule.get('risk_score', 0),
                'severity': rule.get('severity', 'medium').lower(),
                'type': rule.get('type', 'query'),
                'query': rule.get('query', ''),
                'index': rule.get('index', []),
                'language': rule.get('language', 'kuery'),
                'false_positives': rule.get('false_positives', []),
                'references': rule.get('references', []),
                'tags': rule.get('tags', []),
                'enabled': rule.get('enabled', True),
                'interval': rule.get('interval', '5m'),
                'from': rule.get('from', 'now-6m'),
                'threat': rule.get('threat', []),
                'threshold': rule.get('threshold', {}),
                'timestamp_override': rule.get('timestamp_override'),
                'file_path': file_path,
                'content_hash': hashlib.sha256(content.encode()).hexdigest()
            }
            
            # Extract creation/modification dates
            if metadata:
                parsed['creation_date'] = metadata.get('creation_date')
                parsed['updated_date'] = metadata.get('updated_date') or metadata.get('modified_date')
                parsed['maturity'] = metadata.get('maturity', 'production')
                parsed['min_stack_version'] = metadata.get('min_stack_version')
            
            # Extract MITRE techniques from threat array
            mitre_techniques = []
            for threat_item in parsed['threat']:
                if 'technique' in threat_item:
                    for technique in threat_item['technique']:
                        tech_id = technique.get('id', '')
                        if tech_id:
                            mitre_techniques.append(tech_id)
                        # Also get subtechniques
                        for subtech in technique.get('subtechnique', []):
                            if subtech.get('id'):
                                mitre_techniques.append(subtech['id'])
                                
            parsed['mitre_techniques'] = mitre_techniques
            
            # Extract platform from tags
            platforms = []
            for tag in parsed['tags']:
                if tag.startswith('OS:'):
                    platforms.append(tag[3:].lower())
                elif tag in ['Windows', 'Linux', 'macOS', 'Network']:
                    platforms.append(tag.lower())
            parsed['platforms'] = platforms
            
            # Extract data sources from index patterns
            data_sources = []
            for idx in parsed['index']:
                if 'winlogbeat' in idx:
                    data_sources.append('winlogbeat')
                elif 'filebeat' in idx:
                    data_sources.append('filebeat')
                elif 'packetbeat' in idx:
                    data_sources.append('packetbeat')
                elif 'auditbeat' in idx:
                    data_sources.append('auditbeat')
                elif 'logs-endpoint' in idx:
                    data_sources.append('elastic-endpoint')
            parsed['data_sources'] = list(set(data_sources))
            
            return parsed
            
        except Exception as e:
            logger.error(f"Error parsing rule file {file_path}: {e}")
            self.stats['parse_errors'] += 1
            return None
    
    def _manual_field_extraction(self, content: str, file_path: str) -> Optional[Dict[str, Any]]:
        """Manually extract critical fields when TOML parsing fails"""
        try:
            # Extract rule ID
            rule_id_match = re.search(r'rule_id\s*=\s*["\']([^"\']+)["\']', content)
            if not rule_id_match:
                return None
            
            # Extract name
            name_match = re.search(r'name\s*=\s*["\']([^"\']+)["\']', content)
            
            # Extract description (may be multiline)
            desc_match = re.search(r'description\s*=\s*(?:"""([^"]*)"""|\'\'\'([^\']*)\'\'\'|["\']([^"\']+)["\'])', content, re.DOTALL)
            
            # Extract severity
            severity_match = re.search(r'severity\s*=\s*["\']([^"\']+)["\']', content)
            
            # Extract risk_score
            risk_match = re.search(r'risk_score\s*=\s*(\d+)', content)
            
            # Extract type
            type_match = re.search(r'type\s*=\s*["\']([^"\']+)["\']', content)
            
            # Extract tags array
            tags = []
            tags_match = re.search(r'tags\s*=\s*\[(.*?)\]', content, re.DOTALL)
            if tags_match:
                tags_str = tags_match.group(1)
                tags = re.findall(r'["\']([^"\']+)["\']', tags_str)
            
            # Extract MITRE techniques from threat array
            mitre_techniques = []
            threat_section = re.search(r'\[\[rule\.threat\]\](.*?)(?:\[\[|\Z)', content, re.DOTALL)
            if threat_section:
                technique_ids = re.findall(r'id\s*=\s*["\']([T]\d{4}(?:\.\d{3})?)["\']', threat_section.group(1))
                mitre_techniques = list(set(technique_ids))
            
            # Build minimal rule structure
            return {
                'rule': {
                    'rule_id': rule_id_match.group(1),
                    'name': name_match.group(1) if name_match else file_path,
                    'description': (desc_match.group(1) or desc_match.group(2) or desc_match.group(3)) if desc_match else '',
                    'severity': severity_match.group(1) if severity_match else 'medium',
                    'risk_score': int(risk_match.group(1)) if risk_match else 50,
                    'type': type_match.group(1) if type_match else 'query',
                    'tags': tags,
                    'threat': [{'technique': [{'id': t} for t in mitre_techniques]}] if mitre_techniques else [],
                    'query': 'PARSE_ERROR: Complex query could not be extracted',
                    'index': [],
                    'language': 'kuery',
                    'enabled': True
                }
            }
        except Exception as e:
            logger.debug(f"Manual extraction failed for {file_path}: {e}")
            return None
    
    def process_archive(self, archive_path: str, version: str) -> List[Dict[str, Any]]:
        """Process downloaded archive and extract rules"""
        rules = []
        
        with zipfile.ZipFile(archive_path, 'r') as zip_ref:
            # Extract to temp directory
            with tempfile.TemporaryDirectory() as extract_dir:
                zip_ref.extractall(extract_dir)
                
                # Find rules directory - structure is usually:
                # elastic-detection-rules-{hash}/rules/
                base_dir = Path(extract_dir)
                rules_dirs = list(base_dir.glob('*/rules'))
                
                if not rules_dirs:
                    logger.error("No rules directory found in archive")
                    return rules
                    
                rules_dir = rules_dirs[0]
                logger.info(f"Processing rules from: {rules_dir}")
                
                # Process all TOML files
                for toml_file in rules_dir.rglob('*.toml'):
                    self.stats['total_files'] += 1
                    
                    # Get relative path for categorization
                    rel_path = toml_file.relative_to(rules_dir)
                    category = rel_path.parts[0] if len(rel_path.parts) > 1 else 'uncategorized'
                    self.stats['categories'].add(category)
                    
                    try:
                        content = toml_file.read_text(encoding='utf-8')
                        parsed = self.parse_rule_file(content, str(rel_path))
                        
                        if parsed:
                            parsed['category'] = category
                            parsed['version'] = version
                            parsed['original_content'] = content
                            rules.append(parsed)
                            self.stats['rules_parsed'] += 1
                            
                    except Exception as e:
                        logger.error(f"Error processing {toml_file}: {e}")
                        self.stats['parse_errors'] += 1
                        
        return rules
    
    def stage_to_s3(self, rules: List[Dict[str, Any]], version: str) -> str:
        """Stage parsed rules to S3"""
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        
        # Create manifest
        manifest = {
            'source': 'elastic',
            'version': version,
            'download_time': timestamp,
            'stats': {
                'total_files': self.stats['total_files'],
                'rules_parsed': self.stats['rules_parsed'],
                'parse_errors': self.stats['parse_errors'],
                'manual_extractions': self.stats['manual_extractions'],
                'skipped_deprecated': self.stats['skipped_deprecated'],
                'categories': list(self.stats['categories'])
            },
            'rule_count': len(rules)
        }
        
        # Upload rules in batches
        batch_size = 100
        batch_keys = []
        
        for i in range(0, len(rules), batch_size):
            batch = rules[i:i+batch_size]
            batch_num = i // batch_size
            
            batch_key = f"{ELASTIC_PREFIX}/{timestamp}/rules_batch_{batch_num:04d}.json"
            
            s3_client.put_object(
                Bucket=STAGING_BUCKET,
                Key=batch_key,
                Body=json.dumps(batch, default=str),
                ContentType='application/json'
            )
            
            batch_keys.append(batch_key)
            logger.info(f"Uploaded batch {batch_num} with {len(batch)} rules")
        
        # Upload manifest
        manifest['batch_keys'] = batch_keys
        manifest_key = f"{ELASTIC_PREFIX}/{timestamp}/manifest.json"
        
        s3_client.put_object(
            Bucket=STAGING_BUCKET,
            Key=manifest_key,
            Body=json.dumps(manifest, default=str),
            ContentType='application/json'
        )
        
        logger.info(f"Staged {len(rules)} rules to S3 with manifest: {manifest_key}")
        return manifest_key


def lambda_handler(event, context):
    """Main Lambda handler"""
    
    try:
        downloader = ElasticRuleDownloader()
        
        # Download rules
        logger.info("Starting Elastic rules download")
        archive_path, version = downloader.download_rules()
        
        # Process archive
        logger.info("Processing downloaded archive")
        rules = downloader.process_archive(archive_path, version)
        
        if not rules:
            logger.error("No rules extracted from archive")
            return {
                'statusCode': 500,
                'body': json.dumps({'error': 'No rules found'})
            }
        
        # Stage to S3
        manifest_key = downloader.stage_to_s3(rules, version)
        
        # Trigger processor Lambda
        processor_name = os.environ.get('PROCESSOR_LAMBDA', 'pano-elastic-processor')
        
        try:
            lambda_client.invoke(
                FunctionName=processor_name,
                InvocationType='Event',  # Async
                Payload=json.dumps({
                    'manifest_key': manifest_key,
                    'bucket': STAGING_BUCKET
                })
            )
            logger.info(f"Triggered processor Lambda: {processor_name}")
        except Exception as e:
            logger.error(f"Failed to trigger processor: {e}")
        
        # Cleanup
        try:
            os.unlink(archive_path)
        except:
            pass
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Successfully downloaded and staged Elastic rules',
                'manifest_key': manifest_key,
                'stats': {
                    'version': version,
                    'rules_count': len(rules),
                    'categories': list(downloader.stats['categories']),
                    'parse_errors': downloader.stats['parse_errors']
                }
            })
        }
        
    except Exception as e:
        logger.error(f"Lambda execution failed: {e}", exc_info=True)
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e)
            })
        }