"""
Detection rules API endpoints
"""

import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from collections import defaultdict

from sqlalchemy import func, and_, or_, desc, asc, text
from sqlalchemy.orm import joinedload, selectinload

from panorama_datamodel import db_session
from panorama_datamodel.models import (
    DetectionRule, RuleSource, MitreTechnique, MitreTactic, CveEntry,
    RuleMitreMapping, RuleCveMapping
)
from api_utils.response_helpers import create_api_response, create_error_response

logger = logging.getLogger(__name__)


def apply_search_filters(query, params: Dict[str, Any]):
    """Apply search filters to query with optimized JSONB operations"""
    
    # Text search
    if params.get('query'):
        search_term = f'%{params["query"]}%'
        search_conditions = [
            DetectionRule.name.ilike(search_term),
            DetectionRule.description.ilike(search_term),
            DetectionRule.rule_id.ilike(search_term)
        ]
        query = query.filter(or_(*search_conditions))
    
    # Basic filters
    if params.get('rule_types'):
        query = query.filter(DetectionRule.rule_type.in_(params['rule_types']))
    
    if params.get('severities'):
        query = query.filter(DetectionRule.severity.in_(params['severities']))
    
    if params.get('rule_sources'):
        # Convert to integers for source IDs
        source_ids = []
        for source in params['rule_sources']:
            try:
                source_ids.append(int(source))
            except ValueError:
                continue
        if source_ids:
            query = query.filter(DetectionRule.source_id.in_(source_ids))
    
    if params.get('tags'):
        for tag in params['tags']:
            query = query.filter(DetectionRule.tags.contains([tag]))
    
    if 'is_active' in params:
        query = query.filter(DetectionRule.is_active == params['is_active'])
    
    # JSONB metadata filters
    if params.get('rule_platforms'):
        query = query.filter(
            DetectionRule.rule_metadata['rule_platforms'].contains(params['rule_platforms'])
        )
    
    if params.get('mitre_techniques'):
        query = query.filter(
            DetectionRule.rule_metadata['extracted_mitre_techniques'].contains(params['mitre_techniques'])
        )
    
    if params.get('cve_ids'):
        query = query.filter(
            DetectionRule.rule_metadata['extracted_cve_ids'].contains(params['cve_ids'])
        )
    
    if params.get('siem_platforms'):
        query = query.filter(
            DetectionRule.rule_metadata['siem_platform'].astext.in_(params['siem_platforms'])
        )
    
    if params.get('aors'):
        query = query.filter(
            DetectionRule.rule_metadata['aor'].astext.in_(params['aors'])
        )
    
    if params.get('data_sources'):
        query = query.filter(
            DetectionRule.rule_metadata['data_sources'].contains(params['data_sources'])
        )
    
    # Boolean filters for enrichment
    if params.get('has_mitre'):
        query = query.filter(
            func.jsonb_array_length(DetectionRule.rule_metadata['extracted_mitre_techniques']) > 0
        )
    
    if params.get('has_cves'):
        query = query.filter(
            func.jsonb_array_length(DetectionRule.rule_metadata['extracted_cve_ids']) > 0
        )
    
    return query


def serialize_rule_summary(rule: DetectionRule) -> Dict[str, Any]:
    """Serialize rule for list view"""
    return {
        'id': rule.id,
        'rule_id': rule.rule_id,
        'name': rule.name,
        'description': rule.description,
        'rule_type': rule.rule_type,
        'severity': rule.severity,
        'is_active': rule.is_active,
        'tags': rule.tags or [],
        'updated_date': rule.updated_date.isoformat() if rule.updated_date else None,
        'source': {
            'id': rule.source.id,
            'name': rule.source.name
        } if rule.source else None,
        'mitre_technique_count': len(rule.mitre_mappings) if hasattr(rule, 'mitre_mappings') else 0,
        'cve_count': len(rule.cve_mappings) if hasattr(rule, 'cve_mappings') else 0
    }


def serialize_rule_detail(
    rule: DetectionRule,
    mitre_techniques: List[Dict] = None,
    cve_references: List[Dict] = None
) -> Dict[str, Any]:
    """Serialize complete rule details"""
    
    metadata = rule.rule_metadata or {}
    
    return {
        'id': rule.id,
        'rule_id': rule.rule_id,
        'name': rule.name,
        'description': rule.description,
        'rule_content': rule.rule_content,
        'rule_type': rule.rule_type,
        'severity': rule.severity,
        'confidence_score': float(rule.confidence_score) if rule.confidence_score else None,
        'false_positive_rate': float(rule.false_positive_rate) if rule.false_positive_rate else None,
        'is_active': rule.is_active,
        'tags': rule.tags or [],
        'created_date': rule.created_date.isoformat() if rule.created_date else None,
        'updated_date': rule.updated_date.isoformat() if rule.updated_date else None,
        'hash': rule.hash,
        'source': {
            'id': rule.source.id,
            'name': rule.source.name,
            'source_type': rule.source.source_type
        } if rule.source else None,
        'mitre_techniques': mitre_techniques or [],
        'cve_references': cve_references or [],
        'metadata': {
            'info_controls': metadata.get('info_controls'),
            'siem_platform': metadata.get('siem_platform'),
            'aor': metadata.get('aor'),
            'source_org': metadata.get('source_org'),
            'data_sources': metadata.get('data_sources', []),
            'author': metadata.get('author'),
            'modified_by': metadata.get('modified_by'),
            'hunt_id': metadata.get('hunt_id'),
            'malware_family': metadata.get('malware_family'),
            'intrusion_set': metadata.get('intrusion_set'),
            'cwe_ids': metadata.get('cwe_ids', []),
            'validation': metadata.get('validation', {}),
            'references': metadata.get('references', [])
        }
    }


def search_rules(params: Dict[str, Any]) -> Dict[str, Any]:
    """Search detection rules with filters"""
    try:
        with db_session() as session:
            # Build base query
            query = session.query(DetectionRule).options(
                joinedload(DetectionRule.source),
                selectinload(DetectionRule.mitre_mappings),
                selectinload(DetectionRule.cve_mappings)
            )
            
            # Apply filters
            query = apply_search_filters(query, params)
            
            # Sorting
            sort_by = params.get('sort_by', 'updated_date')
            sort_dir = params.get('sort_dir', 'desc')
            
            sort_mapping = {
                'name': DetectionRule.name,
                'severity': DetectionRule.severity,
                'created_date': DetectionRule.created_date,
                'updated_date': DetectionRule.updated_date,
                'rule_type': DetectionRule.rule_type,
                'confidence_score': DetectionRule.confidence_score
            }
            
            sort_column = sort_mapping.get(sort_by, DetectionRule.updated_date)
            
            if sort_dir == 'desc':
                query = query.order_by(desc(sort_column))
            else:
                query = query.order_by(asc(sort_column))
            
            # Get total count before pagination
            total = query.count()
            
            # Pagination
            offset = params.get('offset', 0)
            limit = params.get('limit', 25)
            
            rules = query.offset(offset).limit(limit).all()
            
            # Serialize results
            serialized_rules = [serialize_rule_summary(rule) for rule in rules]
            
            response_data = {
                'items': serialized_rules,
                'total': total,
                'offset': offset,
                'limit': limit,
                'has_more': (offset + limit) < total
            }
            
            return create_api_response(200, response_data)
            
    except Exception as e:
        logger.error(f"Error searching rules: {e}", exc_info=True)
        return create_error_response(500, "Failed to search rules")


def get_rule_details(rule_id: str) -> Dict[str, Any]:
    """Get detailed information for a specific rule"""
    try:
        with db_session() as session:
            # Query rule with all relationships
            if rule_id.isdigit():
                rule = session.query(DetectionRule).options(
                    joinedload(DetectionRule.source),
                    selectinload(DetectionRule.mitre_mappings).joinedload(RuleMitreMapping.technique),
                    selectinload(DetectionRule.cve_mappings).joinedload(RuleCveMapping.cve)
                ).filter(DetectionRule.id == int(rule_id)).first()
            else:
                rule = session.query(DetectionRule).options(
                    joinedload(DetectionRule.source),
                    selectinload(DetectionRule.mitre_mappings).joinedload(RuleMitreMapping.technique),
                    selectinload(DetectionRule.cve_mappings).joinedload(RuleCveMapping.cve)
                ).filter(DetectionRule.rule_id == rule_id).first()
            
            if not rule:
                return create_error_response(404, f"Rule {rule_id} not found")
            
            # Build MITRE techniques list
            mitre_techniques = []
            if rule.mitre_mappings:
                for mapping in rule.mitre_mappings:
                    if mapping.technique:
                        technique_data = {
                            'technique_id': mapping.technique.technique_id,
                            'name': mapping.technique.name,
                            'description': mapping.technique.description[:200] if mapping.technique.description else '',
                            'tactic': mapping.technique.tactic.name if mapping.technique.tactic else None,
                            'platforms': mapping.technique.platforms or [],
                            'mapping_confidence': float(mapping.mapping_confidence) if mapping.mapping_confidence else 1.0,
                            'is_deprecated': mapping.technique.is_deprecated or False,
                            'revoked': mapping.technique.revoked or False
                        }
                        
                        if mapping.technique.superseded_by:
                            technique_data['superseded_by'] = mapping.technique.superseded_by
                        
                        mitre_techniques.append(technique_data)
            
            # Build CVE references list
            cve_references = []
            if rule.cve_mappings:
                for mapping in rule.cve_mappings:
                    if mapping.cve:
                        cve_references.append({
                            'cve_id': mapping.cve.cve_id,
                            'description': mapping.cve.description[:500] if mapping.cve.description else '',
                            'severity': mapping.cve.severity,
                            'cvss_v3_score': float(mapping.cve.cvss_v3_score) if mapping.cve.cvss_v3_score else None,
                            'published_date': mapping.cve.published_date.isoformat() if mapping.cve.published_date else None
                        })
            
            # Serialize rule details
            response_data = serialize_rule_detail(rule, mitre_techniques, cve_references)
            
            # Add deprecation information
            deprecated_count = sum(1 for tech in mitre_techniques if tech.get('is_deprecated') or tech.get('revoked'))
            if deprecated_count > 0:
                response_data['has_deprecated_techniques'] = True
                response_data['deprecated_techniques_count'] = deprecated_count
            
            return create_api_response(200, response_data)
            
    except Exception as e:
        logger.error(f"Error fetching rule {rule_id}: {e}", exc_info=True)
        return create_error_response(500, f"Failed to fetch rule {rule_id}")


def get_enrichment_stats(params: Dict[str, Any]) -> Dict[str, Any]:
    """Get enrichment statistics for rules"""
    try:
        with db_session() as session:
            # Build query with filters
            query = session.query(DetectionRule)
            query = apply_search_filters(query, params)
            
            total_rules = query.count()
            
            # MITRE enrichment stats
            mitre_enriched = query.filter(
                func.jsonb_array_length(DetectionRule.rule_metadata['extracted_mitre_techniques']) > 0
            ).count()
            
            # CVE enrichment stats
            cve_enriched = query.filter(
                func.jsonb_array_length(DetectionRule.rule_metadata['extracted_cve_ids']) > 0
            ).count()
            
            # Both enrichments
            both_enriched = query.filter(
                and_(
                    func.jsonb_array_length(DetectionRule.rule_metadata['extracted_mitre_techniques']) > 0,
                    func.jsonb_array_length(DetectionRule.rule_metadata['extracted_cve_ids']) > 0
                )
            ).count()
            
            response_data = {
                'total_rules': total_rules,
                'enrichment': {
                    'mitre': {
                        'count': mitre_enriched,
                        'percentage': round((mitre_enriched / total_rules * 100), 2) if total_rules > 0 else 0
                    },
                    'cve': {
                        'count': cve_enriched,
                        'percentage': round((cve_enriched / total_rules * 100), 2) if total_rules > 0 else 0
                    },
                    'both': {
                        'count': both_enriched,
                        'percentage': round((both_enriched / total_rules * 100), 2) if total_rules > 0 else 0
                    }
                },
                'by_source': {}
            }
            
            # Stats by source
            sources = session.query(RuleSource).filter(RuleSource.is_active == True).all()
            for source in sources:
                source_query = query.filter(DetectionRule.source_id == source.id)
                source_total = source_query.count()
                
                if source_total > 0:
                    response_data['by_source'][source.name] = {
                        'total': source_total,
                        'mitre_enriched': source_query.filter(
                            func.jsonb_array_length(DetectionRule.rule_metadata['extracted_mitre_techniques']) > 0
                        ).count(),
                        'cve_enriched': source_query.filter(
                            func.jsonb_array_length(DetectionRule.rule_metadata['extracted_cve_ids']) > 0
                        ).count()
                    }
            
            return create_api_response(200, response_data)
            
    except Exception as e:
        logger.error(f"Error getting enrichment stats: {e}", exc_info=True)
        return create_error_response(500, "Failed to get enrichment statistics")


def export_rules(params: Dict[str, Any]) -> Dict[str, Any]:
    """Export rules in various formats"""
    try:
        export_format = params.get('format', 'json')
        include_content = params.get('include_content', False)
        
        with db_session() as session:
            # Build query with filters
            query = session.query(DetectionRule).options(
                joinedload(DetectionRule.source)
            )
            query = apply_search_filters(query, params)
            
            # Limit export size
            max_export = 5000
            rules = query.limit(max_export).all()
            
            if export_format == 'json':
                # JSON export
                export_data = []
                for rule in rules:
                    rule_data = serialize_rule_summary(rule)
                    if include_content:
                        rule_data['rule_content'] = rule.rule_content
                    export_data.append(rule_data)
                
                return create_api_response(200, {
                    'format': 'json',
                    'rules_count': len(export_data),
                    'data': export_data
                })
                
            elif export_format == 'csv':
                # CSV export - return as structured data
                csv_data = []
                for rule in rules:
                    csv_data.append({
                        'rule_id': rule.rule_id,
                        'name': rule.name,
                        'severity': rule.severity,
                        'rule_type': rule.rule_type,
                        'source': rule.source.name if rule.source else '',
                        'is_active': rule.is_active,
                        'tags': ', '.join(rule.tags) if rule.tags else '',
                        'mitre_techniques': ', '.join(rule.rule_metadata.get('extracted_mitre_techniques', [])),
                        'cve_ids': ', '.join(rule.rule_metadata.get('extracted_cve_ids', [])),
                        'updated_date': rule.updated_date.isoformat() if rule.updated_date else ''
                    })
                
                return create_api_response(200, {
                    'format': 'csv',
                    'rules_count': len(csv_data),
                    'data': csv_data
                })
            
            else:
                return create_error_response(400, f"Unsupported export format: {export_format}")
                
    except Exception as e:
        logger.error(f"Error exporting rules: {e}", exc_info=True)
        return create_error_response(500, "Failed to export rules")