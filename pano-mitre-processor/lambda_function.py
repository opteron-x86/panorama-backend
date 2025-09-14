"""
Panorama MITRE Enricher Lambda
"""
import json
import logging
import re
from typing import Set, List, Dict, Any, Tuple, Optional
from datetime import datetime

from panorama_datamodel import db_session
from panorama_datamodel.models import DetectionRule, MitreTechnique, RuleMitreMapping

logger = logging.getLogger()
logger.setLevel(logging.INFO)

class MitreEnricher:
    TECHNIQUE_ID_PATTERN = re.compile(r'T(\d{4})(?:\.(\d{3}))?', re.IGNORECASE)
    
    TECHNIQUE_PATTERNS = {
        'explicit_id': re.compile(r'\bT\d{4}(?:\.\d{3})?\b', re.IGNORECASE),
        'mitre_reference': re.compile(r'mitre.*att&ck.*T\d{4}', re.IGNORECASE),
        'attack_reference': re.compile(r'att&ck.*T\d{4}', re.IGNORECASE),
        'technique_context': re.compile(r'technique\s+T\d{4}', re.IGNORECASE)
    }
        
    def __init__(self):
        self.processed_count = 0
        self.mappings_created = 0
        self.mappings_updated = 0
        self.techniques_found = 0
        self.confidence_scores = []
        self._technique_cache = None
        self._technique_name_lookup = None
        
    def enrich_rules(self, rule_ids: List[int] = None) -> Dict[str, Any]:
        logger.info(f"Starting MITRE enrichment for {len(rule_ids) if rule_ids else 'all'} rules")
        
        with db_session() as session:
            rules = self._get_rules_to_process(session, rule_ids)
            
            if not rules:
                logger.info("No rules found for MITRE enrichment")
                return self._create_result_summary()
            
            logger.info(f"Processing {len(rules)} rules for MITRE enrichment")
            
            valid_techniques = self._load_valid_techniques(session)
            logger.info(f"Loaded {len(valid_techniques)} valid MITRE techniques")
            
            batch_size = 250
            for i in range(0, len(rules), batch_size):
                batch = rules[i:i + batch_size]
                self._process_rule_batch(batch, valid_techniques, session)
                
                session.commit()
                
                batch_num = i//batch_size + 1
                total_batches = (len(rules)-1)//batch_size + 1
                logger.info(f"Processed batch {batch_num}/{total_batches} ({len(batch)} rules)")
            
            logger.info(f"MITRE enrichment complete: {self._create_result_summary()}")
            return self._create_result_summary()
    
    def _get_rules_to_process(self, session, rule_ids: List[int] = None) -> List[DetectionRule]:
        """Get rules that need MITRE enrichment."""
        query = session.query(DetectionRule).filter(DetectionRule.is_active == True)
        
        if rule_ids:
            query = query.filter(DetectionRule.id.in_(rule_ids))
        
        return query.all()
    
    def _load_valid_techniques(self, session) -> Dict[str, MitreTechnique]:
        """Load all valid MITRE techniques for validation AND create lookup cache."""
        techniques = session.query(MitreTechnique).filter(
            (MitreTechnique.is_deprecated == False) | (MitreTechnique.is_deprecated == None),
            (MitreTechnique.revoked == False) | (MitreTechnique.revoked == None)
        ).all()
        
        technique_dict = {tech.technique_id.upper(): tech for tech in techniques}
        
        self._build_technique_lookup_cache(techniques)
        
        logger.info(f"Loaded {len(technique_dict)} valid MITRE techniques")
        
        return technique_dict

    def _check_deprecated_mappings(self, rule: DetectionRule, session) -> List[str]:
        """Check if rule has existing mappings to deprecated techniques."""
        deprecated_techniques = []
        
        existing_mappings = session.query(
            RuleMitreMapping, MitreTechnique
        ).join(
            MitreTechnique, RuleMitreMapping.technique_id == MitreTechnique.id
        ).filter(
            RuleMitreMapping.rule_id == rule.id,
            MitreTechnique.is_deprecated == True
        ).all()
        
        for mapping, technique in existing_mappings:
            deprecated_techniques.append(technique.technique_id)
            logger.warning(f"Rule {rule.id} has mapping to deprecated technique: {technique.technique_id}")
        
        return deprecated_techniques

    def _build_technique_lookup_cache(self, techniques: List[MitreTechnique]):
        """Build efficient lookup structures for technique name matching."""
        self._technique_name_lookup = {}
        
        for technique in techniques:
            if not technique.name:
                continue
                
            technique_name_lower = technique.name.lower()
            
            self._technique_name_lookup[technique_name_lower] = {
                'technique_id': technique.technique_id,
                'confidence': 0.8
            }
            
            key_terms = {
                'process injection': technique.technique_id if 'injection' in technique_name_lower else None,
                'powershell': technique.technique_id if 'powershell' in technique_name_lower else None,
                'registry': technique.technique_id if 'registry' in technique_name_lower else None,
                'scheduled': technique.technique_id if 'scheduled' in technique_name_lower else None,
                'persistence': technique.technique_id if 'persistence' in technique_name_lower else None,
                'escalation': technique.technique_id if 'escalation' in technique_name_lower else None,
                'evasion': technique.technique_id if 'evasion' in technique_name_lower else None,
                'dumping': technique.technique_id if 'dumping' in technique_name_lower else None,
                'phishing': technique.technique_id if 'phishing' in technique_name_lower else None,
                'lateral': technique.technique_id if 'lateral' in technique_name_lower else None,
                'remote': technique.technique_id if 'remote' in technique_name_lower else None,
                'command': technique.technique_id if 'command' in technique_name_lower else None
            }
            
            for term, tech_id in key_terms.items():
                if tech_id and term not in self._technique_name_lookup:
                    self._technique_name_lookup[term] = {
                        'technique_id': tech_id,
                        'confidence': 0.6
                    }
        
        logger.info(f"Built technique lookup cache with {len(self._technique_name_lookup)} entries")
    
    def _process_rule_batch(self, rules: List[DetectionRule], valid_techniques: Dict[str, MitreTechnique], session):
        """Process a batch of rules for MITRE enrichment."""
        for rule in rules:
            try:
                self._enrich_single_rule(rule, valid_techniques, session)
                self.processed_count += 1
            except Exception as e:
                logger.error(f"Failed to process rule {rule.id}: {e}")
    
    def _enrich_single_rule(self, rule: DetectionRule, valid_techniques: Dict[str, MitreTechnique], session):
        """Enrich a single rule with MITRE technique mappings."""
        extracted_techniques = self._extract_techniques_from_rule(rule)
        
        deprecated_mappings = self._check_deprecated_mappings(rule, session)
        
        if not extracted_techniques and not deprecated_mappings:
            return
        
        self.techniques_found += len(extracted_techniques)
        
        deprecation_warnings = []
        
        for technique_info in extracted_techniques:
            technique_id = technique_info['id']
            confidence = technique_info['confidence']
            source = technique_info['source']
            
            if technique_id in valid_techniques:
                technique = valid_techniques[technique_id]
                mapping_created = self._create_or_update_mapping(
                    rule, technique, confidence, source, session
                )
                
                if mapping_created:
                    self.confidence_scores.append(confidence)
            else:
                deprecated_tech = session.query(MitreTechnique).filter_by(
                    technique_id=technique_id,
                    is_deprecated=True
                ).first()
                
                if deprecated_tech:
                    deprecation_warnings.append(technique_id)
                    logger.warning(f"Skipped deprecated technique {technique_id} for rule {rule.id}")
                else:
                    logger.debug(f"MITRE technique {technique_id} not found in database (rule {rule.id})")
        
        if deprecated_mappings or deprecation_warnings:
            self._add_deprecation_metadata(rule, deprecated_mappings, deprecation_warnings, session)

    def _add_deprecation_metadata(self, rule: DetectionRule, existing_deprecated: List[str], 
                                attempted_deprecated: List[str], session):
        """Add deprecation warnings to rule metadata."""
        if not rule.rule_metadata:
            rule.rule_metadata = {}
        
        warnings = []
        if existing_deprecated:
            warnings.append(f"Has mappings to deprecated techniques: {', '.join(existing_deprecated)}")
        if attempted_deprecated:
            warnings.append(f"References deprecated techniques: {', '.join(attempted_deprecated)}")
        
        if warnings:
            rule.rule_metadata['deprecation_warnings'] = warnings
            rule.rule_metadata['deprecation_check_date'] = datetime.utcnow().isoformat()
            session.add(rule)
    
    def _extract_techniques_from_rule(self, rule: DetectionRule) -> List[Dict[str, Any]]:
        """Extract MITRE technique references from rule content."""
        techniques = []
        seen = set()
        
        # Check tags first for explicit technique references (highest confidence)
        if rule.tags:
            for tag in rule.tags:
                if tag.lower().startswith('attack.t'):
                    tech_id = tag.split('.')[-1].upper()
                    tech_id = self._normalize_technique_id(tech_id)
                    if tech_id and tech_id not in seen:
                        techniques.append({
                            'id': tech_id,
                            'confidence': 1.0,
                            'source': 'tag_explicit'
                        })
                        seen.add(tech_id)
        
        sources_to_check = [
            (rule.name, 'name', 0.9),
            (rule.description, 'description', 0.8),
            (rule.rule_content, 'content', 0.7),
            (' '.join(rule.tags) if rule.tags else '', 'tags', 0.85)
        ]
        
        if rule.rule_metadata:
            if isinstance(rule.rule_metadata, dict):
                if 'mitre_techniques' in rule.rule_metadata:
                    mitre_techs = rule.rule_metadata['mitre_techniques']
                    if isinstance(mitre_techs, list):
                        for tech in mitre_techs:
                            if isinstance(tech, str) and tech not in seen:
                                techniques.append({
                                    'id': tech.upper(),
                                    'confidence': 0.95,
                                    'source': 'metadata'
                                })
                                seen.add(tech.upper())
                
                if 'extracted_mitre_techniques' in rule.rule_metadata:
                    extracted = rule.rule_metadata['extracted_mitre_techniques']
                    if isinstance(extracted, list):
                        for tech in extracted:
                            if isinstance(tech, str) and tech.upper() not in seen:
                                techniques.append({
                                    'id': tech.upper(),
                                    'confidence': 0.95,
                                    'source': 'metadata_extracted'
                                })
                                seen.add(tech.upper())
        
        for text, source_type, base_confidence in sources_to_check:
            if not text:
                continue
            
            for pattern_name, pattern in self.TECHNIQUE_PATTERNS.items():
                matches = pattern.findall(text)
                for match in matches:
                    technique_id = match if isinstance(match, str) else match[0]
                    
                    technique_id = self._normalize_technique_id(technique_id)
                    if technique_id and technique_id not in seen:
                        confidence = base_confidence
                        if pattern_name == 'explicit_id':
                            confidence = min(1.0, confidence + 0.1)
                        
                        techniques.append({
                            'id': technique_id,
                            'confidence': confidence,
                            'source': f"{source_type}_{pattern_name}"
                        })
                        seen.add(technique_id)
        
        return techniques
    
    def _normalize_technique_id(self, technique_id: str) -> Optional[str]:
        """Normalize and validate a MITRE technique ID."""
        if not technique_id:
            return None
        
        technique_id = technique_id.upper().strip()
        
        if not technique_id.startswith('T'):
            technique_id = 'T' + technique_id
        
        match = self.TECHNIQUE_ID_PATTERN.match(technique_id)
        if match:
            main_id = match.group(1)
            sub_id = match.group(2)
            
            if sub_id:
                return f"T{main_id}.{sub_id}"
            else:
                return f"T{main_id}"
        
        return None
    
    def _create_or_update_mapping(self, rule: DetectionRule, technique: MitreTechnique, 
                                 confidence: float, source: str, session) -> bool:
        """Create or update a MITRE technique mapping for a rule."""
        existing = session.query(RuleMitreMapping).filter_by(
            rule_id=rule.id,
            technique_id=technique.id
        ).first()
        
        if existing:
            if existing.mapping_confidence < confidence:
                existing.mapping_confidence = confidence
                existing.mapping_source = source
                existing.updated_date = datetime.utcnow()
                self.mappings_updated += 1
                return True
            return False
        else:
            mapping = RuleMitreMapping(
                rule_id=rule.id,
                technique_id=technique.id,
                mapping_confidence=confidence,
                mapping_source=source
            )
            session.add(mapping)
            self.mappings_created += 1
            return True
    
    def _create_result_summary(self) -> Dict[str, Any]:
        """Create a summary of the enrichment results."""
        avg_confidence = sum(self.confidence_scores) / len(self.confidence_scores) if self.confidence_scores else 0
        
        return {
            'processed_rules': self.processed_count,
            'techniques_found': self.techniques_found,
            'mappings_created': self.mappings_created,
            'mappings_updated': self.mappings_updated,
            'average_confidence': round(avg_confidence, 2),
            'timestamp': datetime.utcnow().isoformat()
        }

def lambda_handler(event, context):
    """
    Lambda handler for MITRE enrichment.
    
    Event format:
    {
        "rule_ids": [1, 2, 3, ...],  // Optional: specific rules to enrich
        "orchestrator_id": "mitre_20241201_120000"  // Optional: tracking ID
    }
    """
    enricher = MitreEnricher()
    
    try:
        rule_ids = event.get('rule_ids')
        orchestrator_id = event.get('orchestrator_id', 'manual')
        
        logger.info(f"Starting MITRE enrichment (orchestrator: {orchestrator_id})")
        
        result = enricher.enrich_rules(rule_ids)
        
        result.update({
            'statusCode': 200,
            'orchestrator_id': orchestrator_id,
            'timestamp': datetime.utcnow().isoformat(),
            'message': 'MITRE enrichment completed successfully'
        })
        
        logger.info(f"MITRE enrichment complete: {result}")
        return result
        
    except Exception as e:
        error_msg = f"MITRE enrichment failed: {e}"
        logger.error(error_msg, exc_info=True)
        return {
            'statusCode': 500,
            'error': str(e),
            'message': error_msg,
            'orchestrator_id': event.get('orchestrator_id', 'manual')
        }