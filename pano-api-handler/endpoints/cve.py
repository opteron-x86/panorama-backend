"""
CVE API endpoints
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from collections import defaultdict

from sqlalchemy import func, and_, or_, desc, asc, extract
from sqlalchemy.orm import joinedload, selectinload

from panorama_datamodel import db_session
from panorama_datamodel.models import (
    CveEntry, DetectionRule, RuleCveMapping
)
from api_utils.response_helpers import create_api_response, create_error_response

logger = logging.getLogger(__name__)


def search_cves(params: Dict[str, Any]) -> Dict[str, Any]:
    """Search CVEs with filtering and pagination"""
    try:
        with db_session() as session:
            # Build base query
            query = session.query(CveEntry)
            
            # Text search
            if params.get('query'):
                search_term = f'%{params["query"]}%'
                query = query.filter(
                    or_(
                        CveEntry.cve_id.ilike(search_term),
                        CveEntry.description.ilike(search_term)
                    )
                )
            
            # Severity filter
            if params.get('severities'):
                query = query.filter(CveEntry.severity.in_(params['severities']))
            
            # CVSS score range
            if params.get('cvss_min'):
                query = query.filter(CveEntry.cvss_v3_score >= params['cvss_min'])
            
            if params.get('cvss_max'):
                query = query.filter(CveEntry.cvss_v3_score <= params['cvss_max'])
            
            # Date range filter
            if params.get('start_date'):
                try:
                    start_date = datetime.fromisoformat(params['start_date'])
                    query = query.filter(CveEntry.published_date >= start_date)
                except ValueError:
                    logger.warning(f"Invalid start_date: {params['start_date']}")
            
            if params.get('end_date'):
                try:
                    end_date = datetime.fromisoformat(params['end_date'])
                    query = query.filter(CveEntry.published_date <= end_date)
                except ValueError:
                    logger.warning(f"Invalid end_date: {params['end_date']}")
            
            # Filter by whether CVE has associated rules
            if params.get('with_rules_only'):
                query = query.join(RuleCveMapping).distinct()
            
            # Sorting
            sort_by = params.get('sort_by', 'published_date')
            sort_dir = params.get('sort_dir', 'desc')
            
            sort_mapping = {
                'cve_id': CveEntry.cve_id,
                'published_date': CveEntry.published_date,
                'modified_date': CveEntry.modified_date,
                'cvss_score': CveEntry.cvss_v3_score,
                'severity': CveEntry.severity
            }
            
            sort_column = sort_mapping.get(sort_by, CveEntry.published_date)
            
            if sort_dir == 'desc':
                query = query.order_by(desc(sort_column))
            else:
                query = query.order_by(asc(sort_column))
            
            # Get total count
            total = query.count()
            
            # Pagination
            offset = params.get('offset', 0)
            limit = params.get('limit', 25)
            cves = query.offset(offset).limit(limit).all()
            
            # Serialize results
            cve_data = []
            for cve in cves:
                # Get associated rule count
                rule_count = session.query(func.count(RuleCveMapping.id)).filter(
                    RuleCveMapping.cve_id == cve.id
                ).scalar()
                
                cve_dict = {
                    'id': cve.id,
                    'cve_id': cve.cve_id,
                    'description': cve.description,
                    'published_date': cve.published_date.isoformat() if cve.published_date else None,
                    'modified_date': cve.modified_date.isoformat() if cve.modified_date else None,
                    'severity': cve.severity,
                    'cvss_v3_score': float(cve.cvss_v3_score) if cve.cvss_v3_score else None,
                    'cvss_v3_vector': cve.cvss_v3_vector,
                    'cwe_ids': cve.cwe_ids or [],
                    'affected_products': cve.affected_products or [],
                    'references': cve.cve_references or [],
                    'rule_count': rule_count
                }
                
                cve_data.append(cve_dict)
            
            response_data = {
                'data': cve_data,
                'total': total,
                'offset': offset,
                'limit': limit,
                'has_more': (offset + limit) < total
            }
            
            return create_api_response(200, response_data)
            
    except Exception as e:
        logger.error(f"Error searching CVEs: {e}", exc_info=True)
        return create_error_response(500, "Failed to search CVEs")


def get_cve_details(cve_id: str) -> Dict[str, Any]:
    """Get detailed information for a specific CVE"""
    try:
        with db_session() as session:
            # Query CVE with associated rules
            cve = session.query(CveEntry).options(
                selectinload(CveEntry.rule_mappings).joinedload(RuleCveMapping.rule)
            ).filter(CveEntry.cve_id == cve_id).first()
            
            if not cve:
                return create_error_response(404, f"CVE {cve_id} not found")
            
            # Build associated rules list
            associated_rules = []
            if cve.rule_mappings:
                for mapping in cve.rule_mappings:
                    if mapping.rule:
                        associated_rules.append({
                            'rule_id': mapping.rule.rule_id,
                            'name': mapping.rule.name,
                            'severity': mapping.rule.severity,
                            'rule_type': mapping.rule.rule_type,
                            'confidence_score': float(mapping.confidence_score) if mapping.confidence_score else 1.0,
                            'relationship_type': mapping.relationship_type
                        })
            
            # Build detailed response
            response_data = {
                'id': cve.id,
                'cve_id': cve.cve_id,
                'description': cve.description,
                'published_date': cve.published_date.isoformat() if cve.published_date else None,
                'modified_date': cve.modified_date.isoformat() if cve.modified_date else None,
                'severity': cve.severity,
                'cvss_v3_score': float(cve.cvss_v3_score) if cve.cvss_v3_score else None,
                'cvss_v3_vector': cve.cvss_v3_vector,
                'cvss_v2_score': float(cve.cvss_v2_score) if cve.cvss_v2_score else None,
                'cvss_v2_vector': cve.cvss_v2_vector,
                'cwe_ids': cve.cwe_ids or [],
                'affected_products': cve.affected_products or [],
                'references': cve.references or [],
                'source_identifier': cve.source_identifier,
                'vulnerability_status': cve.vulnerability_status,
                'associated_rules': associated_rules,
                'rule_count': len(associated_rules)
            }
            
            return create_api_response(200, response_data)
            
    except Exception as e:
        logger.error(f"Error fetching CVE {cve_id}: {e}", exc_info=True)
        return create_error_response(500, f"Failed to fetch CVE {cve_id}")


def get_cve_stats(params: Dict[str, Any]) -> Dict[str, Any]:
    """Get CVE statistics and analytics"""
    try:
        with db_session() as session:
            # Base query with optional filters
            base_query = session.query(CveEntry)
            
            # Apply date range if provided
            if params.get('start_date'):
                try:
                    start_date = datetime.fromisoformat(params['start_date'])
                    base_query = base_query.filter(CveEntry.published_date >= start_date)
                except ValueError:
                    pass
            
            if params.get('end_date'):
                try:
                    end_date = datetime.fromisoformat(params['end_date'])
                    base_query = base_query.filter(CveEntry.published_date <= end_date)
                except ValueError:
                    pass
            
            # Total CVEs
            total_cves = base_query.count()
            
            # CVEs with rules
            cves_with_rules = base_query.join(RuleCveMapping).distinct().count()
            
            # Severity distribution
            severity_stats = {}
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                count = base_query.filter(CveEntry.severity == severity).count()
                severity_stats[severity.lower()] = count
            
            # CVSS score distribution
            cvss_ranges = [
                (9.0, 10.0, 'critical'),
                (7.0, 8.9, 'high'),
                (4.0, 6.9, 'medium'),
                (0.1, 3.9, 'low'),
                (0.0, 0.0, 'none')
            ]
            
            cvss_distribution = {}
            for min_score, max_score, label in cvss_ranges:
                if label == 'none':
                    count = base_query.filter(
                        or_(
                            CveEntry.cvss_v3_score == 0,
                            CveEntry.cvss_v3_score == None
                        )
                    ).count()
                else:
                    count = base_query.filter(
                        and_(
                            CveEntry.cvss_v3_score >= min_score,
                            CveEntry.cvss_v3_score <= max_score
                        )
                    ).count()
                cvss_distribution[label] = count
            
            # Recent CVEs (last 30 days)
            thirty_days_ago = datetime.now() - timedelta(days=30)
            recent_cves = base_query.filter(
                CveEntry.published_date >= thirty_days_ago
            ).count()
            
            # CVEs by year
            current_year = datetime.now().year
            cves_by_year = {}
            for year in range(current_year - 4, current_year + 1):
                year_count = base_query.filter(
                    extract('year', CveEntry.published_date) == year
                ).count()
                cves_by_year[str(year)] = year_count
            
            # Top CWEs
            top_cwes = defaultdict(int)
            cves_with_cwes = base_query.filter(CveEntry.cwe_ids != None).all()
            for cve in cves_with_cwes:
                if cve.cwe_ids:
                    for cwe in cve.cwe_ids[:3]:  # Limit to first 3 CWEs per CVE
                        top_cwes[cwe] += 1
            
            # Sort and limit top CWEs
            top_cwes_list = sorted(
                [{'cwe_id': k, 'count': v} for k, v in top_cwes.items()],
                key=lambda x: x['count'],
                reverse=True
            )[:10]
            
            # Most targeted products
            product_stats = defaultdict(int)
            cves_with_products = base_query.filter(CveEntry.affected_products != None).limit(1000).all()
            for cve in cves_with_products:
                if cve.affected_products:
                    for product in cve.affected_products[:5]:  # Limit processing
                        if isinstance(product, dict):
                            vendor = product.get('vendor', 'unknown')
                            product_stats[vendor] += 1
                        elif isinstance(product, str):
                            product_stats[product] += 1
            
            top_products = sorted(
                [{'product': k, 'cve_count': v} for k, v in product_stats.items()],
                key=lambda x: x['cve_count'],
                reverse=True
            )[:10]
            
            response_data = {
                'total_cves': total_cves,
                'cves_with_rules': cves_with_rules,
                'coverage_percentage': round(
                    (cves_with_rules / total_cves * 100) if total_cves > 0 else 0,
                    2
                ),
                'severity_distribution': severity_stats,
                'cvss_distribution': cvss_distribution,
                'recent_cves_30d': recent_cves,
                'cves_by_year': cves_by_year,
                'top_cwes': top_cwes_list,
                'top_affected_products': top_products,
                'metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'filters_applied': {
                        'start_date': params.get('start_date'),
                        'end_date': params.get('end_date')
                    }
                }
            }
            
            return create_api_response(200, response_data)
            
    except Exception as e:
        logger.error(f"Error generating CVE stats: {e}", exc_info=True)
        return create_error_response(500, "Failed to generate CVE statistics")