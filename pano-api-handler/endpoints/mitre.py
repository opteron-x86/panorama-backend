"""
MITRE ATT&CK API endpoints
"""

import logging
from typing import Dict, Any, List, Optional
from collections import defaultdict

from sqlalchemy import func, and_, or_, desc, asc, distinct
from sqlalchemy.orm import joinedload, selectinload

from panorama_datamodel import db_session
from panorama_datamodel.models import (
    MitreTactic, MitreTechnique, DetectionRule, 
    RuleMitreMapping, MitreGroup, MitreSoftware
)
from api_utils.response_helpers import create_api_response, create_error_response

logger = logging.getLogger(__name__)


def get_mitre_matrix(params: Dict[str, Any]) -> Dict[str, Any]:
    """Build MITRE ATT&CK matrix with coverage information"""
    try:
        with db_session() as session:
            # Get platform filter if provided
            platforms = params.get('platforms', [])
            
            # Query all tactics with their techniques
            tactics_query = session.query(MitreTactic).order_by(MitreTactic.id)
            tactics = tactics_query.all()
            
            # Build techniques query with optional platform filter
            techniques_query = session.query(MitreTechnique).options(
                joinedload(MitreTechnique.tactic),
                selectinload(MitreTechnique.rule_mappings)
            ).filter(
                MitreTechnique.is_deprecated == False,
                MitreTechnique.revoked == False
            )
            
            if platforms:
                # Filter techniques by platform
                platform_conditions = []
                for platform in platforms:
                    platform_conditions.append(
                        func.array_to_string(MitreTechnique.platforms, ',').ilike(f'%{platform}%')
                    )
                techniques_query = techniques_query.filter(or_(*platform_conditions))
            
            techniques = techniques_query.all()
            
            # Build matrix structure
            matrix = []
            technique_by_tactic = defaultdict(list)
            
            # Group techniques by tactic
            for technique in techniques:
                if technique.tactic:
                    technique_by_tactic[technique.tactic_id].append(technique)
            
            # Build matrix response
            for tactic in tactics:
                tactic_techniques = technique_by_tactic.get(tactic.id, [])
                
                # Calculate coverage for this tactic
                total_techniques = len(tactic_techniques)
                covered_techniques = sum(
                    1 for t in tactic_techniques 
                    if t.rule_mappings and len(t.rule_mappings) > 0
                )
                
                tactic_data = {
                    'id': tactic.id,
                    'tactic_id': tactic.tactic_id,
                    'name': tactic.name,
                    'description': tactic.description,
                    'technique_count': total_techniques,
                    'covered_count': covered_techniques,
                    'coverage_percentage': round(
                        (covered_techniques / total_techniques * 100) if total_techniques > 0 else 0, 
                        2
                    ),
                    'techniques': []
                }
                
                # Add technique details
                for technique in sorted(tactic_techniques, key=lambda t: t.technique_id):
                    rule_count = len(technique.rule_mappings) if technique.rule_mappings else 0
                    
                    technique_data = {
                        'technique_id': technique.technique_id,
                        'name': technique.name,
                        'description': technique.description[:200] if technique.description else '',
                        'platforms': technique.platforms or [],
                        'rule_count': rule_count,
                        'is_covered': rule_count > 0,
                        'is_subtechnique': '.' in technique.technique_id,
                        'parent_technique_id': technique.parent_technique_id
                    }
                    
                    # Add deprecation info if relevant
                    if technique.is_deprecated:
                        technique_data['is_deprecated'] = True
                        technique_data['superseded_by'] = technique.superseded_by
                    
                    tactic_data['techniques'].append(technique_data)
                
                matrix.append(tactic_data)
            
            # Calculate overall statistics
            total_techniques_count = sum(t['technique_count'] for t in matrix)
            total_covered_count = sum(t['covered_count'] for t in matrix)
            
            response_data = {
                'matrix': matrix,
                'metadata': {
                    'total_tactics': len(matrix),
                    'total_techniques': total_techniques_count,
                    'covered_techniques': total_covered_count,
                    'overall_coverage': round(
                        (total_covered_count / total_techniques_count * 100) 
                        if total_techniques_count > 0 else 0, 
                        2
                    ),
                    'platform_filter': platforms if platforms else None
                }
            }
            
            return create_api_response(200, response_data)
            
    except Exception as e:
        logger.error(f"Error building MITRE matrix: {e}", exc_info=True)
        return create_error_response(500, "Failed to build MITRE matrix")


def get_coverage_analysis(params: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze MITRE ATT&CK coverage with detailed metrics"""
    try:
        with db_session() as session:
            platforms = params.get('platforms', [])
            include_details = params.get('include_details', False)
            
            # Base query for techniques
            base_query = session.query(MitreTechnique).filter(
                MitreTechnique.is_deprecated == False,
                MitreTechnique.revoked == False
            )
            
            if platforms:
                platform_conditions = []
                for platform in platforms:
                    platform_conditions.append(
                        MitreTechnique.platforms.contains([platform])
                    )
                base_query = base_query.filter(or_(*platform_conditions))
            
            # Get total techniques
            total_techniques = base_query.count()
            
            # Get covered techniques (those with rule mappings)
            covered_query = base_query.join(RuleMitreMapping).distinct()
            covered_techniques = covered_query.count()
            
            # Calculate coverage percentage
            coverage_percentage = round(
                (covered_techniques / total_techniques * 100) if total_techniques > 0 else 0,
                2
            )
            
            response_data = {
                'total_techniques': total_techniques,
                'covered_techniques': covered_techniques,
                'coverage_percentage': coverage_percentage,
                'platform_filter_applied': platforms if platforms else None
            }
            
            # Add detailed breakdown if requested
            if include_details:
                # Coverage by tactic
                tactics = session.query(MitreTactic).all()
                coverage_by_tactic = []
                
                for tactic in tactics:
                    tactic_query = base_query.filter(
                        MitreTechnique.tactic_id == tactic.id
                    )
                    tactic_total = tactic_query.count()
                    
                    if tactic_total > 0:
                        tactic_covered = tactic_query.join(RuleMitreMapping).distinct().count()
                        coverage_by_tactic.append({
                            'tactic': tactic.name,
                            'tactic_id': tactic.tactic_id,
                            'total': tactic_total,
                            'covered': tactic_covered,
                            'percentage': round((tactic_covered / tactic_total * 100), 2)
                        })
                
                response_data['coverage_by_tactic'] = coverage_by_tactic
                
                # Coverage gaps (uncovered techniques)
                uncovered_techniques = base_query.outerjoin(RuleMitreMapping).filter(
                    RuleMitreMapping.id == None
                ).limit(20).all()
                
                response_data['coverage_gaps'] = [
                    {
                        'technique_id': t.technique_id,
                        'name': t.name,
                        'tactic': t.tactic.name if t.tactic else None,
                        'platforms': t.platforms or []
                    }
                    for t in uncovered_techniques
                ]
                
                # Most covered techniques
                most_covered = session.query(
                    MitreTechnique.technique_id,
                    MitreTechnique.name,
                    func.count(RuleMitreMapping.id).label('rule_count')
                ).join(RuleMitreMapping).group_by(
                    MitreTechnique.id,
                    MitreTechnique.technique_id,
                    MitreTechnique.name
                ).order_by(desc('rule_count')).limit(10).all()
                
                response_data['most_covered_techniques'] = [
                    {
                        'technique_id': row.technique_id,
                        'name': row.name,
                        'rule_count': row.rule_count
                    }
                    for row in most_covered
                ]
            
            return create_api_response(200, response_data)
            
    except Exception as e:
        logger.error(f"Error analyzing coverage: {e}", exc_info=True)
        return create_error_response(500, "Failed to analyze MITRE coverage")


def get_techniques_list(params: Dict[str, Any]) -> Dict[str, Any]:
    """List MITRE techniques with filtering and pagination"""
    try:
        with db_session() as session:
            # Build base query
            query = session.query(MitreTechnique).options(
                joinedload(MitreTechnique.tactic)
            )
            
            # Search filter
            if params.get('search'):
                search_term = f'%{params["search"]}%'
                query = query.filter(
                    or_(
                        MitreTechnique.technique_id.ilike(search_term),
                        MitreTechnique.name.ilike(search_term),
                        MitreTechnique.description.ilike(search_term)
                    )
                )
            
            # Tactic filter
            if params.get('tactic_id'):
                query = query.join(MitreTactic).filter(
                    MitreTactic.tactic_id == params['tactic_id']
                )
            
            # Platform filter
            if params.get('platforms'):
                platform_conditions = []
                for platform in params['platforms']:
                    platform_conditions.append(
                        MitreTechnique.platforms.contains([platform])
                    )
                query = query.filter(or_(*platform_conditions))
            
            # Exclude deprecated/revoked unless requested
            if not params.get('include_deprecated', False):
                query = query.filter(
                    MitreTechnique.is_deprecated == False,
                    MitreTechnique.revoked == False
                )
            
            # Subtechniques filter
            if params.get('subtechniques_only'):
                query = query.filter(MitreTechnique.technique_id.contains('.'))
            elif params.get('exclude_subtechniques'):
                query = query.filter(~MitreTechnique.technique_id.contains('.'))
            
            # Sorting
            sort_by = params.get('sort_by', 'technique_id')
            if sort_by == 'name':
                query = query.order_by(MitreTechnique.name)
            else:
                query = query.order_by(MitreTechnique.technique_id)
            
            # Get total count
            total = query.count()
            
            # Pagination
            offset = params.get('offset', 0)
            limit = params.get('limit', 25)
            techniques = query.offset(offset).limit(limit).all()
            
            # Serialize results
            techniques_data = []
            for technique in techniques:
                # Get rule count
                rule_count = session.query(func.count(RuleMitreMapping.id)).filter(
                    RuleMitreMapping.technique_id == technique.id
                ).scalar()
                
                technique_dict = {
                    'technique_id': technique.technique_id,
                    'name': technique.name,
                    'description': technique.description,
                    'tactic': {
                        'id': technique.tactic.id,
                        'tactic_id': technique.tactic.tactic_id,
                        'name': technique.tactic.name
                    } if technique.tactic else None,
                    'platforms': technique.platforms or [],
                    'kill_chain_phases': technique.kill_chain_phases or [],
                    'data_sources': technique.data_sources or [],
                    'is_subtechnique': '.' in technique.technique_id,
                    'parent_technique_id': technique.parent_technique_id,
                    'rule_count': rule_count,
                    'is_deprecated': technique.is_deprecated,
                    'revoked': technique.revoked
                }
                
                if technique.superseded_by:
                    technique_dict['superseded_by'] = technique.superseded_by
                
                techniques_data.append(technique_dict)
            
            response_data = {
                'techniques': techniques_data,
                'total': total,
                'offset': offset,
                'limit': limit,
                'has_more': (offset + limit) < total
            }
            
            return create_api_response(200, response_data)
            
    except Exception as e:
        logger.error(f"Error listing techniques: {e}", exc_info=True)
        return create_error_response(500, "Failed to list techniques")


def get_tactics_list(params: Dict[str, Any]) -> Dict[str, Any]:
    """List all MITRE tactics with statistics"""
    try:
        with db_session() as session:
            # Query tactics with technique counts
            tactics_data = []
            
            tactics = session.query(MitreTactic).order_by(MitreTactic.id).all()
            
            for tactic in tactics:
                # Count techniques for this tactic
                technique_count = session.query(func.count(MitreTechnique.id)).filter(
                    MitreTechnique.tactic_id == tactic.id,
                    MitreTechnique.is_deprecated == False,
                    MitreTechnique.revoked == False
                ).scalar()
                
                # Count covered techniques
                covered_count = session.query(func.count(distinct(MitreTechnique.id))).join(
                    RuleMitreMapping
                ).filter(
                    MitreTechnique.tactic_id == tactic.id,
                    MitreTechnique.is_deprecated == False,
                    MitreTechnique.revoked == False
                ).scalar()
                
                tactics_data.append({
                    'id': tactic.id,
                    'tactic_id': tactic.tactic_id,
                    'name': tactic.name,
                    'description': tactic.description,
                    'external_references': tactic.external_references or [],
                    'technique_count': technique_count,
                    'covered_techniques': covered_count,
                    'coverage_percentage': round(
                        (covered_count / technique_count * 100) if technique_count > 0 else 0,
                        2
                    )
                })
            
            response_data = {
                'tactics': tactics_data,
                'total': len(tactics_data)
            }
            
            return create_api_response(200, response_data)
            
    except Exception as e:
        logger.error(f"Error listing tactics: {e}", exc_info=True)
        return create_error_response(500, "Failed to list tactics")