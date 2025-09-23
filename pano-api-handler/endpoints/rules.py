import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

from sqlalchemy import and_, or_, desc, asc, func
from sqlalchemy.orm import joinedload, selectinload, contains_eager

from panorama_datamodel import db_session
from panorama_datamodel.models import (
    DetectionRule, RuleSource, RuleMitreMapping, RuleCveMapping,
    MitreTechnique, CveEntry
)
from panorama_datamodel.exceptions import NotFoundError

logger = logging.getLogger(__name__)

def search_rules(params: Dict[str, Any]) -> Dict[str, Any]:
    """Search detection rules with optimized queries"""
    
    with db_session() as session:
        query = session.query(DetectionRule).distinct()
        query = query.options(joinedload(DetectionRule.source))
        
        # Track what we've already joined
        mitre_joined = False
        cve_joined = False
        
        # Text search
        if params.get('query'):
            search_term = f"%{params['query']}%"
            query = query.filter(
                or_(
                    DetectionRule.name.ilike(search_term),
                    DetectionRule.description.ilike(search_term),
                    DetectionRule.rule_id.ilike(search_term)
                )
            )
        
        # Basic filters
        if params.get('rule_types'):
            query = query.filter(DetectionRule.rule_type.in_(params['rule_types']))
        
        if params.get('severities'):
            query = query.filter(DetectionRule.severity.in_(params['severities']))
        
        if params.get('source_ids'):
            query = query.filter(DetectionRule.source_id.in_(params['source_ids']))
        
        if 'is_active' in params:
            query = query.filter(DetectionRule.is_active == params['is_active'])
        
        if params.get('tags'):
            tag_conditions = []
            for tag in params['tags']:
                tag_conditions.append(func.array_position(DetectionRule.tags, tag) != None)
            query = query.filter(or_(*tag_conditions))
        
        # MITRE filter with join tracking
        if params.get('mitre_techniques'):
            query = (query
                .join(RuleMitreMapping)
                .join(MitreTechnique)
                .filter(MitreTechnique.technique_id.in_(params['mitre_techniques']))
                .options(
                    contains_eager(DetectionRule.mitre_mappings)
                    .joinedload(RuleMitreMapping.technique)
                ))
            mitre_joined = True
        
        # CVE filter with join tracking
        if params.get('cve_ids'):
            query = (query
                .join(RuleCveMapping)
                .join(CveEntry)
                .filter(CveEntry.cve_id.in_(params['cve_ids']))
                .options(
                    contains_eager(DetectionRule.cve_mappings)
                    .joinedload(RuleCveMapping.cve)
                ))
            cve_joined = True
        
        # Count before pagination
        total = query.count()
        
        # Sort
        sort_map = {
            'name': DetectionRule.name,
            'severity': DetectionRule.severity,
            'updated_date': DetectionRule.updated_date,
            'created_date': DetectionRule.created_date,
            'rule_type': DetectionRule.rule_type
        }
        sort_col = sort_map.get(params.get('sort_by'), DetectionRule.updated_date)
        order = desc if params.get('sort_dir') == 'desc' else asc
        query = query.order_by(order(sort_col))
        
        # Paginate
        offset = params.get('offset', 0)
        limit = min(params.get('limit', 25), 1000)
        
        # Add loading options only for non-joined relationships
        if not mitre_joined:
            query = query.options(
                selectinload(DetectionRule.mitre_mappings)
                .joinedload(RuleMitreMapping.technique)
            )
        if not cve_joined:
            query = query.options(
                selectinload(DetectionRule.cve_mappings)
                .joinedload(RuleCveMapping.cve)
            )
        
        rules = query.offset(offset).limit(limit).all()
        
        result = {
            'rules': [serialize_rule(rule) for rule in rules],
            'total': total,
            'offset': offset,
            'limit': limit
        }
        
        if params.get('include_stats'):
            result['stats'] = get_stats_efficient(session)
        
        return result

def get_rule(rule_id: str) -> Dict[str, Any]:
    """Get rule with all associations in single query"""
    
    with db_session() as session:
        query = session.query(DetectionRule).options(
            joinedload(DetectionRule.source),
            selectinload(DetectionRule.mitre_mappings).joinedload(RuleMitreMapping.technique).joinedload(MitreTechnique.tactic),
            selectinload(DetectionRule.cve_mappings).joinedload(RuleCveMapping.cve)
        )
        
        if rule_id.isdigit():
            rule = query.filter(DetectionRule.id == int(rule_id)).first()
        else:
            rule = query.filter(DetectionRule.rule_id == rule_id).first()
        
        if not rule:
            raise NotFoundError(f"Rule {rule_id} not found")
        
        return serialize_rule(rule, include_content=True)


def serialize_rule(rule: DetectionRule, include_content: bool = False) -> Dict[str, Any]:
    """Serialize rule without accessing JSONB metadata"""
    
    data = {
        'id': rule.id,
        'rule_id': rule.rule_id,
        'name': rule.name,
        'description': rule.description,
        'severity': rule.severity,
        'rule_type': rule.rule_type,
        'tags': rule.tags or [],
        'is_active': rule.is_active,
        'created_date': rule.created_date.isoformat() if rule.created_date else None,
        'updated_date': rule.updated_date.isoformat() if rule.updated_date else None,
        'source': rule.source.name if rule.source else None
    }
    
    # Use loaded associations, not metadata
    if hasattr(rule, 'mitre_mappings'):
        data['mitre_techniques'] = [
            m.technique.technique_id 
            for m in rule.mitre_mappings 
            if m.technique and not m.technique.is_deprecated
        ]
    else:
        data['mitre_techniques'] = []
    
    if hasattr(rule, 'cve_mappings'):
        data['cves'] = [
            m.cve.cve_id 
            for m in rule.cve_mappings 
            if m.cve
        ]
    else:
        data['cves'] = []
    
    if include_content:
        data['rule_content'] = rule.rule_content
        data['confidence_score'] = float(rule.confidence_score) if rule.confidence_score else None
        
        if hasattr(rule, 'mitre_mappings') and rule.mitre_mappings:
            data['mitre_details'] = [
                {
                    'technique_id': m.technique.technique_id,
                    'name': m.technique.name,
                    'tactic': m.technique.tactic.name if m.technique.tactic else None
                }
                for m in rule.mitre_mappings 
                if m.technique
            ]
        
        if hasattr(rule, 'cve_mappings') and rule.cve_mappings:
            data['cve_details'] = [
                {
                    'cve_id': m.cve.cve_id,
                    'severity': m.cve.severity,
                    'cvss_score': float(m.cve.cvss_v3_score) if m.cve.cvss_v3_score else None
                }
                for m in rule.cve_mappings 
                if m.cve
            ]
    
    return data


def get_stats_efficient(session) -> Dict[str, Any]:
    """Get statistics with efficient queries"""
    
    # Single query for severity counts
    severity_counts = dict(
        session.query(
            DetectionRule.severity,
            func.count(DetectionRule.id)
        ).filter(
            DetectionRule.is_active == True
        ).group_by(DetectionRule.severity).all()
    )
    
    # Single query for source counts
    source_counts = dict(
        session.query(
            RuleSource.name,
            func.count(DetectionRule.id)
        ).join(DetectionRule).filter(
            DetectionRule.is_active == True
        ).group_by(RuleSource.name).all()
    )
    
    # Single query for MITRE/CVE counts
    mitre_count = session.query(
        func.count(func.distinct(RuleMitreMapping.rule_id))
    ).scalar() or 0
    
    cve_count = session.query(
        func.count(func.distinct(RuleCveMapping.rule_id))
    ).scalar() or 0
    
    return {
        'by_severity': severity_counts,
        'by_source': source_counts,
        'with_mitre': mitre_count,
        'with_cves': cve_count
    }