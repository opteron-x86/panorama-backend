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