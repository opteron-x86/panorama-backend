"""
MITRE ATT&CK Enrichment Worker
Processes detection rules to map them to MITRE ATT&CK techniques using:
1. Explicit technique extraction from tags/metadata
2. ML-based similarity matching using rule metadata and query semantics
"""
import os
import re
import json
import logging
from typing import Set, List, Dict, Optional, Any
from datetime import datetime

import yaml
import numpy as np
import boto3
import onnxruntime as ort
from transformers import AutoTokenizer

from panorama_datamodel import db_session
from panorama_datamodel.models import DetectionRule, MitreTechnique, RuleMitreMapping

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Configuration
USE_ML = os.environ.get('USE_ML', 'true').lower() == 'true'
USE_QUERY_FEATURES = os.environ.get('USE_QUERY_FEATURES', 'true').lower() == 'true'
ML_MODEL_BUCKET = os.environ.get('ML_MODEL_BUCKET', 'panorama-ml-models-538269499906')
SIMILARITY_THRESHOLD = float(os.environ.get('SIMILARITY_THRESHOLD', '0.65'))
MAX_ML_SUGGESTIONS = int(os.environ.get('MAX_ML_SUGGESTIONS', '3'))

# Regex patterns for explicit technique extraction
TECHNIQUE_PATTERNS = [
    re.compile(r'\bT\d{4}(?:\.\d{3})?\b', re.IGNORECASE),
    re.compile(r'attack\.t\d{4}(?:\.\d{3})?', re.IGNORECASE),
]

# Field name normalization for semantic extraction
FIELD_SEMANTICS = {
    'CommandLine': 'command execution',
    'Image': 'process',
    'ParentImage': 'parent process',
    'TargetFilename': 'file creation',
    'DestinationIp': 'network connection',
    'DestinationPort': 'network port',
    'DestinationHostname': 'network destination',
    'RegistryKey': 'registry modification',
    'RegistryValue': 'registry value',
    'User': 'user account',
    'EventID': 'event type',
    'ProcessName': 'process name',
    'SourceImage': 'source process',
    'TargetObject': 'target object',
    'TargetImage': 'target process',
    'PipeName': 'named pipe',
    'ServiceName': 'windows service',
    'TaskName': 'scheduled task',
}

SNORT_CLASSTYPE_SEMANTICS = {
    'attempted-admin': 'privilege escalation administrative access',
    'attempted-user': 'initial access user exploitation',
    'trojan-activity': 'command and control malware',
    'web-application-attack': 'web application exploitation',
    'web-application-activity': 'web application interaction',
    'policy-violation': 'defense evasion policy bypass',
    'shellcode-detect': 'code execution shellcode',
    'exploit-kit': 'exploitation framework delivery',
    'attempted-recon': 'reconnaissance network scanning',
    'network-scan': 'reconnaissance discovery',
    'denial-of-service': 'denial of service resource exhaustion',
    'misc-activity': 'suspicious network activity',
    'misc-attack': 'network attack',
    'successful-admin': 'privilege escalation successful',
    'successful-user': 'valid accounts access',
    'protocol-command-decode': 'protocol manipulation',
    'string-detect': 'pattern detection',
    'suspicious-filename-detect': 'file delivery suspicious',
    'suspicious-login': 'credential access authentication',
    'system-call-detect': 'execution system calls',
    'tcp-connection': 'network connection',
    'trojan-activity': 'malware execution',
    'unsuccessful-user': 'credential access failed',
    'web-application-attack': 'exploitation web vulnerability',
    'attempted-dos': 'denial of service attempt',
    'attempted-recon': 'active scanning reconnaissance',
    'bad-unknown': 'unknown malicious activity',
    'default-login-attempt': 'credential access default credentials',
    'icmp-event': 'network protocol icmp',
    'rpc-portmap-decode': 'remote procedure call',
    'decode-of-an-rpc-query': 'rpc enumeration',
    'executable-code-was-detected': 'code execution detected',
    'a-suspicious-string-was-detected': 'suspicious pattern',
    'a-suspicious-filename-was-detected': 'malicious file',
    'an-attempted-login-using-a-suspicious-username-was-detected': 'credential access brute force',
    'a-system-call-was-detected': 'system execution',
    'a-tcp-connection-was-detected': 'network connection established',
    'a-network-trojan-was-detected': 'malware communication',
    'a-client-was-using-an-unusual-port': 'non-standard port',
    'detection-of-a-network-scan': 'network discovery',
    'detection-of-a-denial-of-service-attack': 'resource exhaustion',
    'detection-of-a-non-standard-protocol-or-event': 'protocol anomaly',
    'generic-protocol-command-decode': 'protocol parsing',
    'access-to-a-potentially-vulnerable-web-application': 'web vulnerability',
    'web-application-activity': 'http application interaction',
    'suspicious-string-was-detected': 'malicious pattern',
}

# Model cache
_MODEL_SESSION = None
_TOKENIZER = None
_TECHNIQUE_EMBEDDINGS = None


def normalize_technique_id(technique_id: str) -> Optional[str]:
    """Normalize technique ID to standard format (T1234 or T1234.001)"""
    if not technique_id:
        return None
    
    technique_id = technique_id.upper().strip()
    technique_id = technique_id.replace('ATTACK.', '')
    
    if not technique_id.startswith('T'):
        technique_id = 'T' + technique_id
    
    if re.match(r'^T\d{4}(?:\.\d{3})?$', technique_id):
        return technique_id
    return None


def extract_explicit_techniques(rule: DetectionRule) -> Set[str]:
    """Extract explicitly mentioned technique IDs from rule metadata"""
    techniques = set()
    
    if rule.tags:
        for tag in rule.tags:
            if 'attack.t' in tag.lower():
                tech_id = tag.split('.')[-1]
                if normalized := normalize_technique_id(tech_id):
                    techniques.add(normalized)
    
    if rule.rule_metadata:
        mitre_tags = rule.rule_metadata.get('extracted_mitre_techniques', [])
        for tech_id in mitre_tags:
            if normalized := normalize_technique_id(tech_id):
                techniques.add(normalized)
    
    for pattern in TECHNIQUE_PATTERNS:
        text = f"{rule.name} {rule.description or ''}"
        for match in pattern.finditer(text):
            if normalized := normalize_technique_id(match.group(0)):
                techniques.add(normalized)
    
    return techniques


def extract_query_semantics(rule: DetectionRule) -> str:
    """Extract semantic content from detection query logic"""
    if not rule.rule_content or not USE_QUERY_FEATURES:
        return ""
    
    try:
        if rule.rule_type == 'sigma':
            return _extract_sigma_semantics(rule.rule_content)
        elif rule.rule_type == 'elastic':
            return _extract_kql_semantics(rule.rule_content)
        elif rule.rule_type == 'splunk':
            return _extract_spl_semantics(rule.rule_content)
        elif rule.rule_type == 'snort':
            return _extract_snort_semantics(rule.rule_content)
    except Exception as e:
        logger.debug(f"Query extraction failed for rule {rule.id}: {e}")
    
    return ""


def _extract_sigma_semantics(content: str) -> str:
    """Extract semantic tokens from Sigma YAML"""
    parsed = yaml.safe_load(content)
    tokens = []
    
    logsource = parsed.get('logsource', {})
    tokens.extend(filter(None, [
        logsource.get('product'),
        logsource.get('service'),
        logsource.get('category')
    ]))
    
    detection = parsed.get('detection', {})
    for key, value in detection.items():
        if key == 'condition':
            continue
        
        if isinstance(value, dict):
            for field, patterns in value.items():
                if semantic := _normalize_field(field):
                    tokens.append(semantic)
                
                pattern_list = patterns if isinstance(patterns, list) else [patterns]
                for pattern in pattern_list:
                    if isinstance(pattern, str):
                        if meaning := _extract_pattern_meaning(pattern):
                            tokens.append(meaning)
    
    return ' '.join(tokens)


def _extract_kql_semantics(content: str) -> str:
    """Extract semantic tokens from KQL queries"""
    tokens = []
    
    fields = re.findall(r'(\w+)\s*[:=~]', content)
    for field in fields:
        if semantic := _normalize_field(field):
            tokens.append(semantic)
    
    quoted = re.findall(r'["\']([^"\']+)["\']', content)
    for q in quoted:
        if meaning := _extract_pattern_meaning(q):
            tokens.append(meaning)
    
    return ' '.join(tokens)


def _extract_spl_semantics(content: str) -> str:
    """Extract semantic tokens from SPL queries"""
    tokens = []
    
    sourcetypes = re.findall(r'sourcetype\s*=\s*"?([^"\s]+)', content)
    tokens.extend(sourcetypes)
    
    fields = re.findall(r'(\w+)\s*=', content)
    for field in fields:
        if field not in ['index', 'sourcetype', 'earliest', 'latest', 'search']:
            if semantic := _normalize_field(field):
                tokens.append(semantic)
    
    return ' '.join(tokens)

def _extract_snort_semantics(content: str) -> str:
    """Extract semantic tokens from Snort rule syntax"""
    tokens = []
    
    # Parse action and protocol
    action_match = re.match(r'^\s*(alert|log|pass|activate|dynamic|drop|reject|sdrop)\s+(\w+)', content)
    if action_match:
        action = action_match.group(1)
        protocol = action_match.group(2)
        tokens.append(f"{protocol} protocol")
        
        if action in ['drop', 'reject']:
            tokens.append('blocked traffic')
    
    # Extract classtype (most important for MITRE mapping)
    classtype_match = re.search(r'classtype:\s*([^;]+)', content)
    if classtype_match:
        classtype = classtype_match.group(1).strip()
        if semantic := SNORT_CLASSTYPE_SEMANTICS.get(classtype):
            tokens.append(semantic)
        else:
            tokens.append(classtype.replace('-', ' '))
    
    # Extract message (often contains attack description)
    msg_match = re.search(r'msg:\s*"([^"]+)"', content)
    if msg_match:
        msg = msg_match.group(1)
        # Extract meaningful words, skip generic terms
        msg_tokens = [
            word.lower() for word in re.findall(r'\b[a-z]{4,}\b', msg, re.IGNORECASE)
            if word.lower() not in {'file', 'identify', 'request', 'response', 'detect'}
        ]
        tokens.extend(msg_tokens[:5])  # Limit to avoid noise
    
    # Extract flow direction (indicates attack stage)
    flow_match = re.search(r'flow:\s*([^;]+)', content)
    if flow_match:
        flow = flow_match.group(1)
        if 'to_server' in flow:
            tokens.append('inbound attack')
        if 'to_client' in flow:
            tokens.append('outbound exfiltration')
        if 'established' in flow:
            tokens.append('established connection')
    
    # Extract content patterns (what's being detected)
    content_patterns = re.findall(r'content:\s*"([^"]+)"', content)
    for pattern in content_patterns[:3]:  # Limit to first 3
        if semantic := _extract_network_pattern_meaning(pattern):
            tokens.append(semantic)
    
    # Extract PCRE patterns (often reveal attack techniques)
    pcre_patterns = re.findall(r'pcre:\s*"([^"]+)"', content)
    for pattern in pcre_patterns[:2]:  # Limit to first 2
        if semantic := _extract_regex_pattern_meaning(pattern):
            tokens.append(semantic)
    
    # Protocol-specific modifiers
    if 'http_uri' in content:
        tokens.append('http uri inspection')
    if 'http_header' in content:
        tokens.append('http header inspection')
    if 'http_method' in content:
        tokens.append('http method inspection')
    if 'file_data' in content:
        tokens.append('file content inspection')
    if 'ssl_state' in content or 'ssl_version' in content:
        tokens.append('ssl tls inspection')
    if 'dns_query' in content:
        tokens.append('dns query inspection')
    
    # Flowbits indicate multi-stage attacks
    if 'flowbits:set' in content:
        tokens.append('multi-stage attack')
    
    # Byte_test/byte_jump indicate binary protocol parsing
    if 'byte_test' in content or 'byte_jump' in content:
        tokens.append('binary protocol exploitation')
    
    return ' '.join(tokens)


def _extract_network_pattern_meaning(pattern: str) -> str:
    """Extract semantic meaning from Snort content patterns"""
    pattern_lower = pattern.lower()
    
    # Executable/script extensions
    if any(ext in pattern_lower for ext in ['.exe', '.dll', '.bat', '.ps1', '.vbs', '.js']):
        return 'executable file'
    
    # Common exploit patterns
    if 'admin' in pattern_lower or 'root' in pattern_lower:
        return 'administrative access'
    if 'passwd' in pattern_lower or 'shadow' in pattern_lower:
        return 'credential file access'
    if '/bin/' in pattern_lower or 'cmd.exe' in pattern_lower:
        return 'command execution'
    if 'union' in pattern_lower and 'select' in pattern_lower:
        return 'sql injection'
    if '<script' in pattern_lower or 'javascript:' in pattern_lower:
        return 'cross site scripting'
    if '../' in pattern_lower or '..\\' in pattern_lower:
        return 'directory traversal'
    if '%00' in pattern_lower or 'null byte' in pattern_lower:
        return 'null byte injection'
    
    # Malware/backdoor indicators
    if 'shell' in pattern_lower:
        return 'shell access'
    if 'backdoor' in pattern_lower or 'trojan' in pattern_lower:
        return 'malware implant'
    if 'download' in pattern_lower and ('exec' in pattern_lower or 'run' in pattern_lower):
        return 'remote code execution'
    
    # Network scanning
    if 'nmap' in pattern_lower or 'scan' in pattern_lower:
        return 'network scanning'
    
    # Encoding/obfuscation
    if 'base64' in pattern_lower or pattern.count('%') > 3:
        return 'encoded payload'
    
    return ""


def _extract_regex_pattern_meaning(pattern: str) -> str:
    """Extract semantic meaning from PCRE patterns"""
    pattern_lower = pattern.lower()
    
    # File extension matching
    if re.search(r'\\\.(exe|dll|bat|ps1|vbs|js|jar)', pattern_lower):
        return 'suspicious file type'
    
    # Command injection patterns
    if any(cmd in pattern_lower for cmd in ['cmd', 'bash', 'sh', 'powershell', 'wscript']):
        return 'command injection'
    
    # URL/path manipulation
    if '../' in pattern or '..' in pattern:
        return 'path traversal'
    
    # SQL injection patterns
    if any(sql in pattern_lower for sql in ['union.*select', 'drop.*table', 'insert.*into']):
        return 'sql injection'
    
    # XSS patterns
    if re.search(r'<script|javascript:', pattern_lower):
        return 'cross site scripting'
    
    return ""

def _normalize_field(field: str) -> str:
    """Convert field names to natural language"""
    if field in FIELD_SEMANTICS:
        return FIELD_SEMANTICS[field]
    
    normalized = field.replace('_', ' ').replace('.', ' ').lower()
    return normalized if len(normalized) > 2 else ""


def _extract_pattern_meaning(pattern: str) -> str:
    """Extract semantic meaning from detection patterns"""
    pattern_lower = pattern.lower()
    
    # PowerShell indicators
    if 'powershell' in pattern_lower:
        if any(x in pattern_lower for x in ['-enc', '-e ', 'encodedcommand']):
            return 'encoded powershell'
        if 'downloadstring' in pattern_lower or 'webclient' in pattern_lower:
            return 'powershell download'
        if 'invoke-expression' in pattern_lower or 'iex' in pattern_lower:
            return 'powershell execution'
        return 'powershell'
    
    # Command execution
    if 'cmd.exe' in pattern_lower or 'cmd /c' in pattern_lower:
        return 'command prompt'
    if 'wmic' in pattern_lower:
        return 'wmi execution'
    if 'schtasks' in pattern_lower:
        return 'scheduled task'
    if 'reg.exe' in pattern_lower or 'regedit' in pattern_lower:
        return 'registry modification'
    
    # Lateral movement
    if 'psexec' in pattern_lower:
        return 'psexec lateral movement'
    if 'wmiexec' in pattern_lower:
        return 'wmi lateral movement'
    
    # Network tools
    if 'net.exe' in pattern_lower or 'net1.exe' in pattern_lower:
        return 'net command'
    if 'netsh' in pattern_lower:
        return 'netsh network configuration'
    
    # Credential access
    if 'mimikatz' in pattern_lower:
        return 'credential dumping'
    if 'lsass' in pattern_lower:
        return 'lsass access'
    if 'sam' in pattern_lower and 'reg' in pattern_lower:
        return 'sam registry access'
    
    # File extensions
    if match := re.search(r'\.(exe|dll|ps1|bat|vbs|js|hta|scr)(?:["\s\\]|$)', pattern_lower):
        return f'{match.group(1)} file'
    
    return ""


def get_model_session():
    """Load ONNX model session (cached)"""
    global _MODEL_SESSION
    
    if _MODEL_SESSION is None:
        try:
            model_path = '/tmp/model.onnx'
            if not os.path.exists(model_path):
                logger.info(f"Downloading model from s3://{ML_MODEL_BUCKET}/onnx/model_int8.onnx")
                s3 = boto3.client('s3')
                s3.download_file(ML_MODEL_BUCKET, 'onnx/model_int8.onnx', model_path)
                logger.info(f"Model downloaded, size: {os.path.getsize(model_path)} bytes")
            
            logger.info("Loading ONNX model...")
            _MODEL_SESSION = ort.InferenceSession(model_path)
            logger.info("ONNX model loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load ONNX model: {e}", exc_info=True)
            raise
    
    return _MODEL_SESSION


def get_tokenizer():
    """Load tokenizer (cached)"""
    global _TOKENIZER
    
    if _TOKENIZER is None:
        _TOKENIZER = AutoTokenizer.from_pretrained(
            'sentence-transformers/all-MiniLM-L6-v2',
            cache_dir='/tmp'
        )
    
    return _TOKENIZER


def load_technique_embeddings() -> Dict[str, np.ndarray]:
    """Load pre-computed technique embeddings (cached)"""
    global _TECHNIQUE_EMBEDDINGS
    
    if _TECHNIQUE_EMBEDDINGS is None:
        try:
            cache_path = '/tmp/technique_embeddings.json'
            if not os.path.exists(cache_path):
                logger.info(f"Downloading embeddings from s3://{ML_MODEL_BUCKET}/onnx/technique_embeddings.json")
                s3 = boto3.client('s3')
                s3.download_file(ML_MODEL_BUCKET, 'onnx/technique_embeddings.json', cache_path)
                logger.info(f"Embeddings downloaded, size: {os.path.getsize(cache_path)} bytes")
            
            logger.info("Loading technique embeddings...")
            with open(cache_path) as f:
                data = json.load(f)
            _TECHNIQUE_EMBEDDINGS = {k: np.array(v) for k, v in data.items()}
            logger.info(f"Loaded {len(_TECHNIQUE_EMBEDDINGS)} technique embeddings")
        except Exception as e:
            logger.error(f"Failed to load technique embeddings: {e}", exc_info=True)
            raise
    
    return _TECHNIQUE_EMBEDDINGS


def compute_text_embedding(text: str) -> np.ndarray:
    """Compute embedding for text using cached model"""
    session = get_model_session()
    tokenizer = get_tokenizer()
    
    inputs = tokenizer(
        text,
        padding=True,
        truncation=True,
        max_length=256,
        return_tensors='np'
    )
    
    outputs = session.run(None, {
        'input_ids': inputs['input_ids'].astype(np.int64),
        'attention_mask': inputs['attention_mask'].astype(np.int64)
    })
    
    embeddings = outputs[0][0]
    mask = inputs['attention_mask'][0]
    mask_expanded = np.expand_dims(mask, -1)
    sum_embeddings = np.sum(embeddings * mask_expanded, axis=0)
    sum_mask = np.clip(mask_expanded.sum(axis=0), a_min=1e-9, a_max=None)
    
    return sum_embeddings / sum_mask


def cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    """Compute cosine similarity between two vectors"""
    a_norm = a / np.linalg.norm(a)
    b_norm = b / np.linalg.norm(b)
    return float(np.dot(a_norm, b_norm))


def find_similar_techniques(rule_text: str) -> Dict[str, float]:
    """Find similar techniques using ML embeddings"""
    try:
        technique_embeddings = load_technique_embeddings()
        rule_embedding = compute_text_embedding(rule_text)
        
        similarities = []
        for technique_id, tech_embedding in technique_embeddings.items():
            similarity = cosine_similarity(rule_embedding, tech_embedding)
            if similarity >= SIMILARITY_THRESHOLD:
                similarities.append((technique_id, similarity))
        
        similarities.sort(key=lambda x: x[1], reverse=True)
        return dict(similarities[:MAX_ML_SUGGESTIONS])
    
    except Exception as e:
        logger.debug(f"ML enrichment failed: {e}", exc_info=True)
        return {}


def build_enrichment_text(rule: DetectionRule) -> str:
    """Build text for ML enrichment from rule metadata and query semantics"""
    text_parts = [rule.name]
    
    if rule.description:
        text_parts.append(rule.description[:200])
    
    if rule.tags:
        text_parts.extend([t for t in rule.tags if 'attack' in t.lower()])
    
    if USE_QUERY_FEATURES:
        query_semantics = extract_query_semantics(rule)
        if query_semantics:
            text_parts.append(query_semantics)
    
    return ' '.join(text_parts)


def enrich_rule(
    rule: DetectionRule,
    valid_techniques: Dict[str, MitreTechnique],
    session
) -> Dict[str, Any]:
    """Enrich a single rule with MITRE techniques"""
    explicit_techniques = extract_explicit_techniques(rule)
    ml_techniques = {}
    
    # Debug: log rule details
    logger.info(f"Rule {rule.id} ({rule.rule_type}): {len(explicit_techniques)} explicit techniques")
    
    if len(explicit_techniques) < 2 and USE_ML:
        rule_text = build_enrichment_text(rule)
        
        # Critical: log what we're sending to ML
        logger.info(f"Rule {rule.id} enrichment text ({len(rule_text)} chars): {rule_text[:200]}")
        
        if rule_text:  # Don't call ML with empty text
            ml_techniques = find_similar_techniques(rule_text)
            logger.info(f"Rule {rule.id} ML results: {len(ml_techniques)} techniques found")
        else:
            logger.warning(f"Rule {rule.id} has empty enrichment text")
    else:
        logger.info(f"Rule {rule.id} skipped ML: {len(explicit_techniques)} explicit, USE_ML={USE_ML}")
    
    all_techniques = set(explicit_techniques) | set(ml_techniques.keys())
    mappings_created = 0
    
    for technique_id in all_techniques:
        if technique_id not in valid_techniques:
            logger.debug(f"Technique {technique_id} not in valid techniques")
            continue
        
        technique = valid_techniques[technique_id]
        
        existing = session.query(RuleMitreMapping).filter_by(
            rule_id=rule.id,
            technique_id=technique.id
        ).first()
        
        if existing:
            continue
        
        source = 'regex' if technique_id in explicit_techniques else 'ml'
        confidence = ml_techniques.get(technique_id) if source == 'ml' else None
        
        mapping = RuleMitreMapping(
            rule_id=rule.id,
            technique_id=technique.id,
            source=source,
            confidence=confidence
        )
        session.add(mapping)
        mappings_created += 1
    
    return {
        'mappings_created': mappings_created,
        'explicit_count': len(explicit_techniques),
        'ml_count': len(ml_techniques)
    }



def find_similar_techniques(rule_text: str) -> Dict[str, float]:
    """Find similar techniques using ML embeddings"""
    try:
        technique_embeddings = load_technique_embeddings()
        rule_embedding = compute_text_embedding(rule_text)
        
        similarities = []
        top_scores = []  # Track top 5 for debugging
        
        for technique_id, tech_embedding in technique_embeddings.items():
            similarity = cosine_similarity(rule_embedding, tech_embedding)
            
            if len(top_scores) < 5:
                top_scores.append((technique_id, similarity))
                top_scores.sort(key=lambda x: x[1], reverse=True)
            elif similarity > top_scores[-1][1]:
                top_scores[-1] = (technique_id, similarity)
                top_scores.sort(key=lambda x: x[1], reverse=True)
            
            if similarity >= SIMILARITY_THRESHOLD:
                similarities.append((technique_id, similarity))
        
        # Log top scores for debugging
        logger.info(f"Top 5 similarities: {[(t, f'{s:.3f}') for t, s in top_scores]}")
        logger.info(f"Threshold: {SIMILARITY_THRESHOLD}, Found {len(similarities)} above threshold")
        
        similarities.sort(key=lambda x: x[1], reverse=True)
        return dict(similarities[:MAX_ML_SUGGESTIONS])
    
    except Exception as e:
        logger.error(f"ML enrichment failed: {e}", exc_info=True)
        return {}


def lambda_handler(event, context):
    """Lambda handler for MITRE enrichment"""
    chunk_id = event.get('chunk_id', 0)
    rule_ids = event.get('rule_ids')
    
    try:
        with db_session() as session:
            techniques = session.query(MitreTechnique).filter(
                MitreTechnique.is_deprecated == False
            ).all()
            valid_techniques = {t.technique_id: t for t in techniques}
            
            logger.info(f"Chunk {chunk_id}: Loaded {len(valid_techniques)} valid techniques")
            
            query = session.query(DetectionRule)
            if rule_ids:
                query = query.filter(DetectionRule.id.in_(rule_ids))
            
            rules = query.all()
            logger.info(f"Chunk {chunk_id}: Processing {len(rules)} rules")
            
            total_mappings = 0
            rules_with_explicit = 0
            rules_with_ml = 0
            rules_without_techniques = 0
            
            for rule in rules:
                try:
                    result = enrich_rule(rule, valid_techniques, session)
                    total_mappings += result['mappings_created']
                    
                    if result['explicit_count'] > 0:
                        rules_with_explicit += 1
                    if result['ml_count'] > 0:
                        rules_with_ml += 1
                    if result['mappings_created'] == 0:
                        rules_without_techniques += 1
                
                except Exception as e:
                    logger.error(f"Failed to enrich rule {rule.id}: {e}")
            
            session.commit()
            
            logger.info(
                f"Chunk {chunk_id}: Complete - {total_mappings} mappings, "
                f"{rules_with_explicit} explicit, {rules_with_ml} ML, "
                f"{rules_without_techniques} without techniques"
            )
            
            return {
                'statusCode': 200,
                'chunk_id': chunk_id,
                'rules_processed': len(rules),
                'mappings_created': total_mappings,
                'rules_with_explicit': rules_with_explicit,
                'rules_with_ml': rules_with_ml,
                'rules_without_techniques': rules_without_techniques
            }
    
    except Exception as e:
        logger.error(f"Chunk {chunk_id}: Enrichment failed: {e}", exc_info=True)
        return {
            'statusCode': 500,
            'chunk_id': chunk_id,
            'error': str(e)
        }