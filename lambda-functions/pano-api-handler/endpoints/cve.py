import logging
from typing import Dict, Any
from datetime import datetime, timedelta

from sqlalchemy import func, and_, or_, desc

from panorama_datamodel import db_session
from panorama_datamodel.models import CveEntry, RuleCveMapping
from panorama_datamodel.exceptions import NotFoundError

logger = logging.getLogger(__name__)


def search_cves(params: Dict[str, Any]) -> Dict[str, Any]:
    """Search CVEs with filtering"""
    
    with db_session() as session:
        query = session.query(CveEntry)
        
        if params.get('query'):
            search_term = f"%{params['query']}%"
            query = query.filter(
                or_(
                    CveEntry.cve_id.ilike(search_term),
                    CveEntry.description.ilike(search_term)
                )
            )
        
        if params.get('severities'):
            query = query.filter(CveEntry.severity.in_(params['severities']))
        
        if params.get('days_back'):
            try:
                days = int(params['days_back'])
                cutoff = datetime.now() - timedelta(days=days)
                query = query.filter(CveEntry.published_date >= cutoff)
            except ValueError:
                pass
        
        total = query.count()
        
        query = query.order_by(desc(CveEntry.published_date))
        cves = query.offset(params.get('offset', 0)).limit(params.get('limit', 100)).all()
        
        return {
            'cves': [
                {
                    'cve_id': cve.cve_id,
                    'description': cve.description[:500] if cve.description else '',
                    'severity': cve.severity,
                    'cvss_score': float(cve.cvss_v3_score) if cve.cvss_v3_score else None,
                    'published_date': cve.published_date.isoformat() if cve.published_date else None
                }
                for cve in cves
            ],
            'total': total
        }


def get_cve(cve_id: str) -> Dict[str, Any]:
    """Get specific CVE details"""
    
    with db_session() as session:
        cve = session.query(CveEntry).filter(CveEntry.cve_id == cve_id).first()
        
        if not cve:
            raise NotFoundError(f"CVE {cve_id} not found")
        
        # Get associated rules count
        rule_count = session.query(func.count(RuleCveMapping.id)).filter(
            RuleCveMapping.cve_id == cve.id
        ).scalar()
        
        return {
            'cve_id': cve.cve_id,
            'description': cve.description,
            'severity': cve.severity,
            'cvss_v3_score': float(cve.cvss_v3_score) if cve.cvss_v3_score else None,
            'cvss_v3_vector': cve.cvss_v3_vector,
            'published_date': cve.published_date.isoformat() if cve.published_date else None,
            'modified_date': cve.modified_date.isoformat() if cve.modified_date else None,
            'cwe_ids': cve.cwe_ids or [],
            'rule_count': rule_count
        }