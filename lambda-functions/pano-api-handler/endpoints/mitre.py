import logging
from typing import Dict, Any, List, Optional
from collections import defaultdict

from sqlalchemy import func, and_, or_, distinct
from sqlalchemy.orm import joinedload, selectinload

from panorama_datamodel import db_session
from panorama_datamodel.models import (
    MitreTactic, MitreTechnique, DetectionRule, 
    RuleMitreMapping
)
from panorama_datamodel.exceptions import NotFoundError

logger = logging.getLogger(__name__)

def get_matrix(params: Dict[str, Any]) -> Dict[str, Any]:
    """Build MITRE ATT&CK matrix with coverage"""
    
    with db_session() as session:
        tactics = session.query(MitreTactic).order_by(MitreTactic.id).all()
        
        techniques_query = session.query(MitreTechnique).options(
            joinedload(MitreTechnique.tactic),
            selectinload(MitreTechnique.rule_mappings)
        ).filter(
            MitreTechnique.is_deprecated == False,
            MitreTechnique.revoked == False
        )
        
        if params.get('platforms'):
            # Filter techniques that have any of the requested platforms
            platform_filters = []
            for platform in params['platforms']:
                platform_filters.append(
                    MitreTechnique.platforms.any(platform)
                )
            techniques_query = techniques_query.filter(or_(*platform_filters))
        
        techniques = techniques_query.all()
        
        # Group techniques by tactic
        technique_by_tactic = defaultdict(list)
        for technique in techniques:
            if technique.tactic:
                technique_by_tactic[technique.tactic_id].append({
                    'technique_id': technique.technique_id,
                    'name': technique.name,
                    'rule_count': len(technique.rule_mappings) if technique.rule_mappings else 0
                })
        
        # Build matrix
        matrix = []
        for tactic in tactics:
            tactic_techniques = technique_by_tactic.get(tactic.id, [])
            matrix.append({
                'tactic_id': tactic.tactic_id,
                'name': tactic.name,
                'techniques': tactic_techniques,
                'technique_count': len(tactic_techniques)
            })
        
        return {'matrix': matrix}


def get_techniques(params: Dict[str, Any]) -> Dict[str, Any]:
    """List MITRE techniques with filtering"""
    
    with db_session() as session:
        query = session.query(MitreTechnique).options(
            joinedload(MitreTechnique.tactic)
        )
        
        if params.get('search'):
            search_term = f"%{params['search']}%"
            query = query.filter(
                or_(
                    MitreTechnique.technique_id.ilike(search_term),
                    MitreTechnique.name.ilike(search_term)
                )
            )
        
        if not params.get('include_deprecated', False):
            query = query.filter(
                MitreTechnique.is_deprecated == False,
                MitreTechnique.revoked == False
            )
        
        total = query.count()
        
        query = query.order_by(MitreTechnique.technique_id)
        techniques = query.offset(params.get('offset', 0)).limit(params.get('limit', 100)).all()
        
        return {
            'techniques': [
                {
                    'technique_id': t.technique_id,
                    'name': t.name,
                    'tactic': t.tactic.name if t.tactic else None,
                    'platforms': t.platforms or [],
                    'is_deprecated': t.is_deprecated,
                    'superseded_by': t.superseded_by
                }
                for t in techniques
            ],
            'total': total
        }

def get_technique_detail(technique_id: str) -> Dict[str, Any]:
    """Get detailed information for a specific MITRE technique"""
    
    with db_session() as session:
        technique = session.query(MitreTechnique).options(
            joinedload(MitreTechnique.tactic),
            selectinload(MitreTechnique.rule_mappings).joinedload(RuleMitreMapping.rule)
        ).filter(
            MitreTechnique.technique_id == technique_id
        ).first()
        
        if not technique:
            raise NotFoundError(f"Technique {technique_id} not found")
        
        result = {
            'technique_id': technique.technique_id,
            'name': technique.name,
            'description': technique.description,
            'tactic': {
                'tactic_id': technique.tactic.tactic_id,
                'name': technique.tactic.name
            } if technique.tactic else None,
            'platforms': technique.platforms or [],
            'data_sources': technique.data_sources or [],
            'kill_chain_phases': technique.kill_chain_phases or [],
            'detection_description': technique.detection_description,
            'mitigation_description': technique.mitigation_description,
            'is_deprecated': technique.is_deprecated,
            'deprecated_date': technique.deprecated_date.isoformat() if technique.deprecated_date else None,
            'deprecation_reason': technique.deprecation_reason,
            'revoked': technique.revoked,
            'superseded_by': technique.superseded_by,
            'version': technique.version,
            'created_date': technique.created_date.isoformat() if technique.created_date else None,
            'updated_date': technique.updated_date.isoformat() if technique.updated_date else None,
        }
        
        # Add detection coverage
        if technique.rule_mappings:
            rules = []
            for mapping in technique.rule_mappings:
                if mapping.rule and mapping.rule.is_active:
                    rules.append({
                        'rule_id': mapping.rule.rule_id,
                        'name': mapping.rule.name,
                        'severity': mapping.rule.severity,
                    })
            
            result['detection_rules'] = rules
            result['coverage'] = {
                'rule_count': len(rules),
                'has_coverage': len(rules) > 0,
                'coverage_level': 'high' if len(rules) >= 5 else 'medium' if len(rules) >= 2 else 'low' if len(rules) > 0 else 'none'
            }
        else:
            result['detection_rules'] = []
            result['coverage'] = {
                'rule_count': 0,
                'has_coverage': False,
                'coverage_level': 'none'
            }
        
        # Get related techniques
        related = []
        
        # Check for parent technique
        if technique.parent_technique_id:
            parent = session.query(MitreTechnique).filter(
                MitreTechnique.id == technique.parent_technique_id
            ).first()
            if parent:
                related.append({
                    'technique_id': parent.technique_id,
                    'name': parent.name,
                    'relationship': 'parent'
                })
        
        # Check for subtechniques
        subtechniques = session.query(MitreTechnique).filter(
            MitreTechnique.parent_technique_id == technique.id
        ).all()
        for sub in subtechniques:
            related.append({
                'technique_id': sub.technique_id,
                'name': sub.name,
                'relationship': 'subtechnique'
            })
        
        result['related_techniques'] = related
        
        # Add external references if available
        if technique.external_references:
            result['references'] = technique.external_references
        
        return result