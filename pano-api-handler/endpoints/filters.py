import logging
from typing import Dict, Any  # Missing import
from sqlalchemy import func, text

from panorama_datamodel import db_session
from panorama_datamodel.models import (
    RuleSource, DetectionRule, MitreTactic, MitreTechnique, CveEntry
)

logger = logging.getLogger(__name__)


def get_all_filters() -> Dict[str, Any]:
    """Get all available filter options"""
    
    with db_session() as session:
        filters = {}
        
        # Sources
        sources = session.query(
            RuleSource.id,
            RuleSource.name,
            func.count(DetectionRule.id).label('count')
        ).outerjoin(DetectionRule).filter(
            RuleSource.is_active == True
        ).group_by(RuleSource.id, RuleSource.name).all()
        
        filters['sources'] = [
            {'value': str(s.id), 'label': s.name, 'count': s.count}
            for s in sources
        ]
        
        # Rule types
        types = session.query(
            DetectionRule.rule_type,
            func.count(DetectionRule.id)
        ).filter(
            DetectionRule.rule_type != None
        ).group_by(DetectionRule.rule_type).all()
        
        filters['rule_types'] = [
            {'value': t[0], 'label': t[0], 'count': t[1]}
            for t in types
        ]
        
        # Severities
        filters['severities'] = ['critical', 'high', 'medium', 'low', 'info']
        
        # MITRE tactics
        tactics = session.query(MitreTactic.tactic_id, MitreTactic.name).all()
        filters['tactics'] = [
            {'value': t.tactic_id, 'label': t.name}
            for t in tactics
        ]
        
        # Platforms from MITRE
        platforms_result = session.execute(text("""
            SELECT DISTINCT unnest(platforms) as platform
            FROM mitre_techniques
            WHERE platforms IS NOT NULL
            ORDER BY platform
        """))
        
        filters['platforms'] = [row.platform for row in platforms_result]
        
        return filters