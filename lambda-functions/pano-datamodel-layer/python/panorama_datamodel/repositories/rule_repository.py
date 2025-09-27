"""Repository for detection rules"""
from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime

from sqlalchemy import and_, or_, func, desc, asc
from sqlalchemy.orm import Session, joinedload, selectinload

from .base import BaseRepository
from ..models.rules import DetectionRule, RuleSource
from ..models.mitre import MitreTechnique
from ..models.vulnerabilities import CveEntry
from ..models.relationships import RuleMitreMapping, RuleCveMapping

class RuleRepository(BaseRepository[DetectionRule]):
    
    def __init__(self, session: Session):
        super().__init__(session, DetectionRule)
    
    def get_by_rule_id(self, rule_id: str) -> Optional[DetectionRule]:
        """Get rule by string rule_id or numeric id"""
        if rule_id.isdigit():
            return self.session.query(DetectionRule).filter(
                DetectionRule.id == int(rule_id)
            ).first()
        return self.session.query(DetectionRule).filter(
            DetectionRule.rule_id == rule_id
        ).first()
    
    def get_with_associations(self, rule_id: int) -> Optional[DetectionRule]:
        """Get rule with all associations loaded"""
        return (
            self.session.query(DetectionRule)
            .options(
                joinedload(DetectionRule.source),
                selectinload(DetectionRule.mitre_mappings).joinedload(RuleMitreMapping.technique),
                selectinload(DetectionRule.cve_mappings).joinedload(RuleCveMapping.cve)
            )
            .filter(DetectionRule.id == rule_id)
            .first()
        )
    

    def search(
        self,
        query: Optional[str] = None,
        rule_types: Optional[List[str]] = None,
        severities: Optional[List[str]] = None,
        source_ids: Optional[List[int]] = None,
        tags: Optional[List[str]] = None,
        is_active: Optional[bool] = None,
        mitre_techniques: Optional[List[str]] = None,
        cve_ids: Optional[List[str]] = None,
        offset: int = 0,
        limit: int = 100
    ) -> Tuple[List[DetectionRule], int]:
        """Search rules using relationships only"""
        
        query_builder = self.session.query(DetectionRule).distinct()
        
        if query:
            search_term = f'%{query}%'
            query_builder = query_builder.filter(
                or_(
                    DetectionRule.name.ilike(search_term),
                    DetectionRule.description.ilike(search_term),
                    DetectionRule.rule_id.ilike(search_term)
                )
            )
        
        # Direct column filters
        if rule_types:
            query_builder = query_builder.filter(DetectionRule.rule_type.in_(rule_types))
        if severities:
            query_builder = query_builder.filter(DetectionRule.severity.in_(severities))
        if source_ids:
            query_builder = query_builder.filter(DetectionRule.source_id.in_(source_ids))
        if is_active is not None:
            query_builder = query_builder.filter(DetectionRule.is_active == is_active)
        
        # Array column filter
        if tags:
            for tag in tags:
                query_builder = query_builder.filter(DetectionRule.tags.contains([tag]))
        
        # Relationship filters
        if mitre_techniques:
            subq = self.session.query(RuleMitreMapping.rule_id).join(MitreTechnique).filter(
                MitreTechnique.technique_id.in_(mitre_techniques)
            ).subquery()
            query_builder = query_builder.filter(DetectionRule.id.in_(subq))
        
        if cve_ids:
            subq = self.session.query(RuleCveMapping.rule_id).join(CveEntry).filter(
                CveEntry.cve_id.in_(cve_ids)
            ).subquery()
            query_builder = query_builder.filter(DetectionRule.id.in_(subq))
        
        total = query_builder.count()
        rules = query_builder.offset(offset).limit(limit).all()
        
        return rules, total
    
    def get_rules_by_mitre_technique(self, technique_id: str) -> List[DetectionRule]:
        """Get rules that detect a specific MITRE technique"""
        return (
            self.session.query(DetectionRule)
            .join(RuleMitreMapping)
            .join(MitreTechnique)
            .filter(MitreTechnique.technique_id == technique_id)
            .filter(DetectionRule.is_active == True)
            .all()
        )
    
    def get_rules_by_cve(self, cve_id: str) -> List[DetectionRule]:
        """Get rules related to a specific CVE"""
        return (
            self.session.query(DetectionRule)
            .join(RuleCveMapping)
            .join(CveEntry)
            .filter(CveEntry.cve_id == cve_id)
            .filter(DetectionRule.is_active == True)
            .all()
        )
