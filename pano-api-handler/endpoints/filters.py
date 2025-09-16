"""
Filter options API endpoint
"""

import logging
from typing import Dict, Any, List
from collections import defaultdict

from sqlalchemy import func, distinct, text

from panorama_datamodel import db_session
from panorama_datamodel.models import (
    DetectionRule, RuleSource, MitreTactic, MitreTechnique, CveEntry
)
from api_utils.response_helpers import create_api_response, create_error_response

logger = logging.getLogger(__name__)


def get_filter_options() -> Dict[str, Any]:
    """Get all available filter options for the UI"""
    try:
        with db_session() as session:
            filter_options = {}
            
            # Rule sources
            try:
                sources = session.query(
                    RuleSource.id,
                    RuleSource.name,
                    func.count(DetectionRule.id).label('rule_count')
                ).outerjoin(DetectionRule).filter(
                    RuleSource.is_active == True
                ).group_by(
                    RuleSource.id,
                    RuleSource.name
                ).order_by(RuleSource.name).all()
                
                filter_options['rule_sources'] = [
                    {
                        'value': str(source.id),
                        'label': source.name,
                        'count': source.rule_count
                    }
                    for source in sources
                ]
            except Exception as e:
                logger.error(f"Error getting rule sources: {e}")
                filter_options['rule_sources'] = []
            
            # Rule types
            try:
                rule_types = session.query(
                    DetectionRule.rule_type,
                    func.count(DetectionRule.id).label('count')
                ).filter(
                    DetectionRule.rule_type != None
                ).group_by(
                    DetectionRule.rule_type
                ).order_by(DetectionRule.rule_type).all()
                
                filter_options['rule_types'] = [
                    {
                        'value': rt.rule_type,
                        'label': rt.rule_type.replace('_', ' ').title(),
                        'count': rt.count
                    }
                    for rt in rule_types
                ]
            except Exception as e:
                logger.error(f"Error getting rule types: {e}")
                filter_options['rule_types'] = []
            
            # Severities
            try:
                severities = session.query(
                    DetectionRule.severity.label('severity'),
                    func.count(DetectionRule.id).label('count')
                ).filter(
                    DetectionRule.severity != None
                ).group_by(
                    DetectionRule.severity
                ).all()
                
                severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
                
                filter_options['severities'] = sorted([
                    {
                        'value': sev.severity,
                        'label': sev.severity.capitalize() if sev.severity else 'Unknown',
                        'count': sev.count
                    }
                    for sev in severities if sev.severity
                ], key=lambda x: severity_order.get(x['value'].lower(), 99))
            except Exception as e:
                logger.error(f"Error getting severities: {e}")
                filter_options['severities'] = []
            
            # MITRE tactics
            try:
                tactics = session.query(
                    MitreTactic.tactic_id,
                    MitreTactic.name
                ).order_by(MitreTactic.id).all()
                
                filter_options['tactics'] = [
                    {
                        'value': tactic.tactic_id,
                        'label': tactic.name
                    }
                    for tactic in tactics
                ]
            except Exception as e:
                logger.error(f"Error getting tactics: {e}")
                filter_options['tactics'] = []

            # Attack platforms from MITRE techniques
            try:
                attack_platforms_result = session.execute(text("""
                    SELECT DISTINCT unnest(platforms) as platform,
                        COUNT(DISTINCT rm.rule_id) as rule_count
                    FROM mitre_techniques mt
                    LEFT JOIN rule_mitre_mappings rm ON mt.id = rm.technique_id
                    WHERE mt.platforms IS NOT NULL
                    GROUP BY platform
                    ORDER BY platform
                """))
                
                filter_options['platforms'] = [
                    {
                        'value': row.platform,
                        'label': row.platform,
                        'count': row.rule_count
                    }
                    for row in attack_platforms_result
                ]
            except Exception as e:
                logger.error(f"Error getting attack platforms: {e}")
                filter_options['platforms'] = []

            # MITRE tactics with counts
            try:
                tactics = session.execute(text("""
                    SELECT mt.tactic_id, mt.name,
                        COUNT(DISTINCT rm.rule_id) as rule_count
                    FROM mitre_tactics mt
                    LEFT JOIN mitre_techniques tech ON tech.tactic_id = mt.id
                    LEFT JOIN rule_mitre_mappings rm ON tech.id = rm.technique_id
                    GROUP BY mt.tactic_id, mt.name, mt.id
                    ORDER BY mt.id
                """))
                
                filter_options['tactics'] = [
                    {
                        'value': tactic.tactic_id,
                        'label': tactic.name,
                        'count': tactic.rule_count
                    }
                    for tactic in tactics
                ]
            except Exception as e:
                logger.error(f"Error getting tactics: {e}")
                filter_options['tactics'] = []
                
            # Rule platforms from metadata - using raw SQL for JSONB array
            try:
                platforms_result = session.execute(text("""
                    SELECT DISTINCT jsonb_array_elements_text(rule_metadata->'rule_platforms') as platform
                    FROM detection_rules
                    WHERE rule_metadata->'rule_platforms' IS NOT NULL
                    AND jsonb_array_length(rule_metadata->'rule_platforms') > 0
                    ORDER BY platform
                """))
                
                filter_options['rule_platforms'] = [
                    {'value': row.platform, 'label': row.platform}
                    for row in platforms_result
                ]
            except Exception as e:
                logger.error(f"Error getting platforms: {e}")
                filter_options['rule_platforms'] = []
            
            # SIEM platforms from metadata
            try:
                siem_platforms = session.query(
                    func.distinct(DetectionRule.rule_metadata['siem_platform'].astext).label('siem')
                ).filter(
                    DetectionRule.rule_metadata['siem_platform'] != None
                ).all()
                
                filter_options['siem_platforms'] = [
                    {'value': sp.siem, 'label': sp.siem}
                    for sp in siem_platforms if sp.siem
                ]
            except Exception as e:
                logger.error(f"Error getting SIEM platforms: {e}")
                filter_options['siem_platforms'] = []
            
            # AORs from metadata
            try:
                aors = session.query(
                    func.distinct(DetectionRule.rule_metadata['aor'].astext).label('aor')
                ).filter(
                    DetectionRule.rule_metadata['aor'] != None
                ).all()
                
                filter_options['aors'] = [
                    {'value': aor.aor, 'label': aor.aor}
                    for aor in aors if aor.aor
                ]
            except Exception as e:
                logger.error(f"Error getting AORs: {e}")
                filter_options['aors'] = []
            
            # Popular tags - using raw SQL for array unnest
            try:
                tags_result = session.execute(text("""
                    SELECT tag, COUNT(*) as count
                    FROM (
                        SELECT unnest(tags) as tag
                        FROM detection_rules
                        WHERE tags IS NOT NULL
                    ) t
                    WHERE tag IS NOT NULL
                    GROUP BY tag
                    ORDER BY count DESC
                    LIMIT 20
                """))
                
                filter_options['popular_tags'] = [
                    {
                        'value': row.tag,
                        'label': row.tag,
                        'count': row.count
                    }
                    for row in tags_result
                ]
            except Exception as e:
                logger.error(f"Error getting popular tags: {e}")
                filter_options['popular_tags'] = []
            
            # CVE severities
            try:
                cve_severities = session.query(
                    func.distinct(CveEntry.severity)
                ).filter(
                    CveEntry.severity != None
                ).all()
                
                filter_options['cve_severities'] = [
                    {'value': sev[0], 'label': sev[0]}
                    for sev in cve_severities if sev[0]
                ]
            except Exception as e:
                logger.error(f"Error getting CVE severities: {e}")
                filter_options['cve_severities'] = []
            
            # Validation statuses - using raw SQL for nested JSONB
            try:
                validation_result = session.execute(text("""
                    SELECT DISTINCT rule_metadata->'validation'->>'status' as status
                    FROM detection_rules
                    WHERE rule_metadata->'validation'->>'status' IS NOT NULL
                """))
                
                filter_options['validation_statuses'] = [
                    {'value': row.status, 'label': row.status.replace('_', ' ').title()}
                    for row in validation_result if row.status
                ]
            except Exception as e:
                logger.error(f"Error getting validation statuses: {e}")
                filter_options['validation_statuses'] = []
            
            # Static options
            filter_options['date_ranges'] = [
                {'value': '7d', 'label': 'Last 7 days'},
                {'value': '30d', 'label': 'Last 30 days'},
                {'value': '90d', 'label': 'Last 90 days'},
                {'value': '180d', 'label': 'Last 6 months'},
                {'value': '365d', 'label': 'Last year'},
                {'value': 'custom', 'label': 'Custom range'}
            ]
            
            filter_options['enrichment_filters'] = [
                {'value': 'has_mitre', 'label': 'Has MITRE mapping'},
                {'value': 'has_cves', 'label': 'Has CVE references'},
                {'value': 'has_both', 'label': 'Has both MITRE and CVE'},
                {'value': 'no_enrichment', 'label': 'No enrichment'}
            ]
            
            filter_options['sort_options'] = [
                {'value': 'updated_date', 'label': 'Last Updated'},
                {'value': 'created_date', 'label': 'Date Created'},
                {'value': 'name', 'label': 'Name'},
                {'value': 'severity', 'label': 'Severity'},
                {'value': 'confidence_score', 'label': 'Confidence Score'},
                {'value': 'rule_type', 'label': 'Rule Type'}
            ]
            
            return create_api_response(200, filter_options)
            
    except Exception as e:
        logger.error(f"Error getting filter options: {e}", exc_info=True)
        return create_error_response(500, "Failed to get filter options")