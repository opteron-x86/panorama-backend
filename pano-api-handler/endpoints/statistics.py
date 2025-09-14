"""
Statistics and analytics API endpoints
"""

import logging
from typing import Dict, Any
from datetime import datetime, timedelta
from collections import defaultdict

from sqlalchemy import func, and_, or_, desc, extract, case

from panorama_datamodel import db_session
from panorama_datamodel.models import (
    DetectionRule, RuleSource, MitreTechnique, CveEntry,
    RuleMitreMapping, RuleCveMapping
)
from api_utils.response_helpers import create_api_response, create_error_response
from endpoints.rules import apply_search_filters

logger = logging.getLogger(__name__)


def handle_get_stats(params: Dict[str, Any]) -> Dict[str, Any]:
    """Get rule statistics with optional filtering"""
    try:
        with db_session() as session:
            query = session.query(DetectionRule)
            query = apply_search_filters(query, params)
            
            total_rules = query.count()
            
            # Severity distribution
            severity_stats = {}
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                count = query.filter(DetectionRule.severity == severity).count()
                severity_stats[severity] = count
            
            # Source distribution
            source_stats = session.query(
                RuleSource.name,
                func.count(DetectionRule.id).label('count')
            ).join(DetectionRule).filter(
                DetectionRule.id.in_(query.with_entities(DetectionRule.id))
            ).group_by(RuleSource.name).all()
            
            by_source = {source.name: source.count for source in source_stats}
            
            # Rule type distribution
            type_stats = session.query(
                DetectionRule.rule_type,
                func.count(DetectionRule.id).label('count')
            ).filter(
                DetectionRule.id.in_(query.with_entities(DetectionRule.id))
            ).group_by(DetectionRule.rule_type).all()
            
            by_type = {rt.rule_type: rt.count for rt in type_stats if rt.rule_type}
            
            # Enrichment statistics
            mitre_enriched = query.filter(
                func.jsonb_array_length(
                    DetectionRule.rule_metadata['extracted_mitre_techniques']
                ) > 0
            ).count()
            
            cve_enriched = query.filter(
                func.jsonb_array_length(
                    DetectionRule.rule_metadata['extracted_cve_ids']
                ) > 0
            ).count()
            
            both_enriched = query.filter(
                and_(
                    func.jsonb_array_length(
                        DetectionRule.rule_metadata['extracted_mitre_techniques']
                    ) > 0,
                    func.jsonb_array_length(
                        DetectionRule.rule_metadata['extracted_cve_ids']
                    ) > 0
                )
            ).count()
            
            response_data = {
                'total_rules': total_rules,
                'stats': {
                    'by_severity': severity_stats,
                    'by_source': by_source,
                    'by_type': by_type
                },
                'enrichment': {
                    'mitre_enriched': mitre_enriched,
                    'cve_enriched': cve_enriched,
                    'both_enriched': both_enriched
                }
            }
            
            if params:
                response_data['active_filters'] = {
                    k: v for k, v in params.items() 
                    if k not in ['offset', 'limit', 'sort_by', 'sort_dir']
                }
            
            return create_api_response(200, response_data)
            
    except Exception as e:
        logger.error(f"Error generating statistics: {e}", exc_info=True)
        return create_error_response(500, "Failed to generate statistics")


def get_dashboard_data(params: Dict[str, Any]) -> Dict[str, Any]:
    """Get comprehensive dashboard statistics"""
    try:
        with db_session() as session:
            # Base metrics
            total_rules = session.query(func.count(DetectionRule.id)).scalar()
            active_rules = session.query(func.count(DetectionRule.id)).filter(
                DetectionRule.is_active == True
            ).scalar()
            
            # Rules by severity
            rules_by_severity = {}
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                count = session.query(func.count(DetectionRule.id)).filter(
                    DetectionRule.severity == severity
                ).scalar()
                rules_by_severity[severity] = count
            
            # Rules by source
            source_data = session.query(
                RuleSource.name,
                func.count(DetectionRule.id).label('count')
            ).join(DetectionRule).group_by(RuleSource.name).all()
            
            rules_by_source = {s.name: s.count for s in source_data}
            
            # Rules by type
            type_data = session.query(
                DetectionRule.rule_type,
                func.count(DetectionRule.id).label('count')
            ).filter(
                DetectionRule.rule_type != None
            ).group_by(DetectionRule.rule_type).all()
            
            rules_by_type = {t.rule_type: t.count for t in type_data}
            
            # Enrichment statistics
            with_mitre = session.query(func.count(DetectionRule.id)).filter(
                func.jsonb_array_length(
                    DetectionRule.rule_metadata['extracted_mitre_techniques']
                ) > 0
            ).scalar()
            
            with_cve = session.query(func.count(DetectionRule.id)).filter(
                func.jsonb_array_length(
                    DetectionRule.rule_metadata['extracted_cve_ids']
                ) > 0
            ).scalar()
            
            with_both = session.query(func.count(DetectionRule.id)).filter(
                and_(
                    func.jsonb_array_length(
                        DetectionRule.rule_metadata['extracted_mitre_techniques']
                    ) > 0,
                    func.jsonb_array_length(
                        DetectionRule.rule_metadata['extracted_cve_ids']
                    ) > 0
                )
            ).scalar()
            
            no_enrichment = total_rules - (with_mitre + with_cve - with_both)
            
            # Recent updates (last 7 days)
            seven_days_ago = datetime.now() - timedelta(days=7)
            recent_updates = session.query(func.count(DetectionRule.id)).filter(
                DetectionRule.updated_date >= seven_days_ago
            ).scalar()
            
            # Coverage metrics
            total_techniques = session.query(func.count(MitreTechnique.id)).filter(
                MitreTechnique.is_deprecated == False,
                MitreTechnique.revoked == False
            ).scalar()
            
            covered_techniques = session.query(
                func.count(func.distinct(RuleMitreMapping.technique_id))
            ).scalar()
            
            mitre_coverage = round(
                (covered_techniques / total_techniques * 100) if total_techniques > 0 else 0,
                2
            )
            
            total_cves = session.query(func.count(CveEntry.id)).scalar()
            covered_cves = session.query(
                func.count(func.distinct(RuleCveMapping.cve_id))
            ).scalar()
            
            cve_coverage = round(
                (covered_cves / total_cves * 100) if total_cves > 0 else 0,
                2
            )
            
            response_data = {
                'total_rules': total_rules,
                'active_rules': active_rules,
                'rules_by_severity': rules_by_severity,
                'rules_by_source': rules_by_source,
                'rules_by_type': rules_by_type,
                'enrichment_stats': {
                    'with_mitre': with_mitre,
                    'with_cve': with_cve,
                    'with_both': with_both,
                    'no_enrichment': no_enrichment
                },
                'recent_updates': recent_updates,
                'coverage_metrics': {
                    'mitre_coverage': mitre_coverage,
                    'cve_coverage': cve_coverage
                }
            }
            
            return create_api_response(200, response_data)
            
    except Exception as e:
        logger.error(f"Error generating dashboard data: {e}", exc_info=True)
        return create_error_response(500, "Failed to generate dashboard data")


def get_trend_analysis(params: Dict[str, Any]) -> Dict[str, Any]:
    """Get trend analysis data for specified period"""
    try:
        period = params.get('period', 'week')
        
        with db_session() as session:
            # Determine date range
            if period == 'day':
                start_date = datetime.now() - timedelta(days=30)
                interval = 'day'
            elif period == 'week':
                start_date = datetime.now() - timedelta(weeks=12)
                interval = 'week'
            elif period == 'month':
                start_date = datetime.now() - timedelta(days=365)
                interval = 'month'
            else:
                start_date = datetime.now() - timedelta(weeks=12)
                interval = 'week'
            
            # Build data points based on interval
            data_points = []
            current_date = start_date
            
            while current_date <= datetime.now():
                if interval == 'day':
                    next_date = current_date + timedelta(days=1)
                elif interval == 'week':
                    next_date = current_date + timedelta(weeks=1)
                else:
                    next_date = current_date + timedelta(days=30)
                
                # Rules added in period
                rules_added = session.query(func.count(DetectionRule.id)).filter(
                    and_(
                        DetectionRule.created_date >= current_date,
                        DetectionRule.created_date < next_date
                    )
                ).scalar()
                
                # Rules updated in period
                rules_updated = session.query(func.count(DetectionRule.id)).filter(
                    and_(
                        DetectionRule.updated_date >= current_date,
                        DetectionRule.updated_date < next_date,
                        DetectionRule.created_date < current_date
                    )
                ).scalar()
                
                # Rules deprecated in period (using is_active flag)
                rules_deprecated = session.query(func.count(DetectionRule.id)).filter(
                    and_(
                        DetectionRule.updated_date >= current_date,
                        DetectionRule.updated_date < next_date,
                        DetectionRule.is_active == False
                    )
                ).scalar()
                
                data_points.append({
                    'date': current_date.isoformat(),
                    'rules_added': rules_added,
                    'rules_updated': rules_updated,
                    'rules_deprecated': rules_deprecated,
                    'enrichment_changes': rules_updated  # Simplified metric
                })
                
                current_date = next_date
            
            response_data = {
                'period': period,
                'data_points': data_points
            }
            
            return create_api_response(200, response_data)
            
    except Exception as e:
        logger.error(f"Error generating trend analysis: {e}", exc_info=True)
        return create_error_response(500, "Failed to generate trend analysis")