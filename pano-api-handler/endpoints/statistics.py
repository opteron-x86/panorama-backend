"""
Statistics and analytics API endpoints
"""

import logging
from typing import Dict, Any
from datetime import datetime, timedelta
from collections import defaultdict

from sqlalchemy import func, and_, or_, desc, extract, case, text, distinct

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
    """
    Single endpoint for dashboard metrics
    """
    try:
        with db_session() as session:
            # Base metrics
            base_metrics = session.query(
                func.count(DetectionRule.id).label('total_rules'),
                func.sum(case((DetectionRule.is_active == True, 1), else_=0)).label('active_rules'),
                func.sum(case((DetectionRule.is_active == False, 1), else_=0)).label('inactive_rules')
            ).one()
            
            # Severity distribution
            severity_stats = session.query(
                DetectionRule.severity,
                func.count(DetectionRule.id).label('count')
            ).group_by(DetectionRule.severity).all()
            
            by_severity = {s.severity: s.count for s in severity_stats if s.severity}
            
            # Platform distribution from JSONB
            platform_query = text("""
                SELECT 
                    platform,
                    COUNT(*) as count
                FROM detection_rules,
                     jsonb_array_elements_text(
                         CASE 
                             WHEN rule_metadata ? 'rule_platforms' 
                             THEN rule_metadata->'rule_platforms'
                             ELSE '[]'::jsonb
                         END
                     ) as platform
                WHERE is_active = true
                GROUP BY platform
                ORDER BY count DESC
            """)
            
            platform_results = session.execute(platform_query).fetchall()
            by_platform = {row.platform: row.count for row in platform_results}
            
            # Source distribution
            source_stats = session.query(
                RuleSource.name,
                func.count(DetectionRule.id).label('count')
            ).join(
                RuleSource, DetectionRule.source_id == RuleSource.id
            ).group_by(RuleSource.name).all()
            
            by_source = {s.name: s.count for s in source_stats}
            
            # MITRE enrichment
            mitre_enriched = session.query(
                func.count(distinct(RuleMitreMapping.rule_id))
            ).scalar() or 0
            
            # CVE enrichment
            cve_enriched = session.query(
                func.count(distinct(RuleCveMapping.rule_id))
            ).scalar() or 0
            
            # Both enrichments
            both_enriched = session.query(
                func.count(distinct(RuleMitreMapping.rule_id))
            ).filter(
                RuleMitreMapping.rule_id.in_(
                    session.query(distinct(RuleCveMapping.rule_id))
                )
            ).scalar() or 0
            
            # MITRE coverage
            total_techniques = session.query(func.count(MitreTechnique.id)).filter(
                MitreTechnique.is_deprecated == False,
                MitreTechnique.revoked == False
            ).scalar() or 0
            
            covered_techniques = session.query(
                func.count(distinct(RuleMitreMapping.technique_id))
            ).scalar() or 0
            
            coverage_percentage = round(
                (covered_techniques / total_techniques * 100) if total_techniques > 0 else 0, 
                1
            )
            
            # Recent activity (7 days)
            seven_days_ago = datetime.now() - timedelta(days=7)
            
            trend_query = text("""
                WITH date_series AS (
                    SELECT generate_series(
                        date_trunc('day', NOW() - INTERVAL '6 days'),
                        date_trunc('day', NOW()),
                        '1 day'::interval
                    )::date AS date
                )
                SELECT 
                    ds.date,
                    COUNT(CASE WHEN dr.created_date::date = ds.date THEN 1 END) as created,
                    COUNT(CASE WHEN dr.updated_date::date = ds.date 
                               AND dr.updated_date != dr.created_date THEN 1 END) as updated
                FROM date_series ds
                LEFT JOIN detection_rules dr ON (
                    dr.created_date::date = ds.date 
                    OR (dr.updated_date::date = ds.date AND dr.updated_date != dr.created_date)
                )
                GROUP BY ds.date
                ORDER BY ds.date
            """)
            
            trend_results = session.execute(trend_query).fetchall()
            
            daily_activity = [
                {
                    'date': row.date.isoformat(),
                    'rules_created': row.created,
                    'rules_updated': row.updated
                }
                for row in trend_results
            ]
            
            response_data = {
                'metrics': {
                    'total_rules': base_metrics.total_rules,
                    'active_rules': base_metrics.active_rules,
                    'inactive_rules': base_metrics.inactive_rules,
                    'rules_with_mitre': mitre_enriched,
                    'rules_with_cves': cve_enriched,
                    'rules_with_both': both_enriched
                },
                'distributions': {
                    'by_severity': by_severity,
                    'by_platform': by_platform,
                    'by_source': by_source
                },
                'coverage': {
                    'total_techniques': total_techniques,
                    'covered_techniques': covered_techniques,
                    'coverage_percentage': coverage_percentage
                },
                'trends': {
                    'daily_activity': daily_activity
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