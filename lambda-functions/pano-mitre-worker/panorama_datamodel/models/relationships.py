"""
Relationship mapping models between different entities
"""
from datetime import datetime
from typing import Optional
from decimal import Decimal

from sqlalchemy import Column, Integer, String, ForeignKey, DECIMAL, TIMESTAMP, Boolean, UniqueConstraint
from sqlalchemy.orm import relationship, Mapped, mapped_column

from .base import Base, TimestampMixin

class RuleMitreMapping(Base, TimestampMixin):
    __tablename__ = 'rule_mitre_mappings'
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rule_id: Mapped[int] = mapped_column(Integer, ForeignKey('detection_rules.id'))
    technique_id: Mapped[int] = mapped_column(Integer, ForeignKey('mitre_techniques.id'))
    source: Mapped[str] = mapped_column(String(20), nullable=False)
    confidence: Mapped[Optional[Decimal]] = mapped_column(DECIMAL(3, 2), nullable=True)
    is_correct: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    feedback_date: Mapped[Optional[datetime]] = mapped_column(TIMESTAMP, nullable=True)
    feedback_user: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    
    # Relationships
    rule: Mapped["DetectionRule"] = relationship("DetectionRule", back_populates="mitre_mappings")
    technique: Mapped["MitreTechnique"] = relationship("MitreTechnique", back_populates="rule_mappings")
    
    __table_args__ = (
        UniqueConstraint('rule_id', 'technique_id', name='unique_rule_technique_mapping'),
    )

# For ML training data extraction
class TrainingDataRepository:
    def get_validated_mappings(self, session):
        """Get human-validated mappings for training"""
        return session.query(
            RuleMitreMapping.rule_id,
            RuleMitreMapping.technique_id,
            RuleMitreMapping.is_correct,
            DetectionRule.name,
            DetectionRule.description,
            DetectionRule.tags,
            MitreTechnique.technique_id.label('technique_code')
        ).join(
            DetectionRule
        ).join(
            MitreTechnique
        ).filter(
            RuleMitreMapping.is_correct.isnot(None)
        ).all()
    
    def get_high_confidence_ml(self, session, threshold=0.85):
        """Get high-confidence ML predictions as pseudo-labels"""
        return session.query(RuleMitreMapping).filter(
            RuleMitreMapping.source == 'ml',
            RuleMitreMapping.confidence >= threshold,
            RuleMitreMapping.is_correct.is_(None)  # Not yet validated
        ).all()
    
    def get_conflicting_mappings(self, session):
        """Find disagreements between regex and ML for review"""
        regex_mappings = session.query(
            RuleMitreMapping.rule_id,
            RuleMitreMapping.technique_id
        ).filter(RuleMitreMapping.source == 'regex')
        
        ml_mappings = session.query(
            RuleMitreMapping.rule_id,
            RuleMitreMapping.technique_id,
            RuleMitreMapping.confidence
        ).filter(RuleMitreMapping.source == 'ml')
        
        # Rules with different techniques from different sources
        return session.query(
            DetectionRule.id,
            DetectionRule.name
        ).join(
            RuleMitreMapping
        ).group_by(
            DetectionRule.id
        ).having(
            func.count(distinct(RuleMitreMapping.source)) > 1
        ).all()

class RuleCveMapping(Base, TimestampMixin):
    __tablename__ = 'rule_cve_mappings'
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rule_id: Mapped[int] = mapped_column(Integer, ForeignKey('detection_rules.id'))
    cve_id: Mapped[int] = mapped_column(Integer, ForeignKey('cve_entries.id'))
    relationship_type: Mapped[str] = mapped_column(String(50))
    confidence_score: Mapped[Decimal] = mapped_column(DECIMAL(3, 2), default=1.00)
    
    # Relationships
    rule: Mapped["DetectionRule"] = relationship("DetectionRule", back_populates="cve_mappings")
    cve: Mapped["CveEntry"] = relationship("CveEntry", back_populates="rule_mappings")
    
    __table_args__ = (
        UniqueConstraint('rule_id', 'cve_id', 'relationship_type', name='unique_rule_cve_relationship'),
    )

class RuleIocMapping(Base, TimestampMixin):
    __tablename__ = 'rule_ioc_mappings'
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rule_id: Mapped[int] = mapped_column(Integer, ForeignKey('detection_rules.id'))
    ioc_id: Mapped[int] = mapped_column(Integer, ForeignKey('iocs.id'))
    relationship_type: Mapped[str] = mapped_column(String(50))
    confidence_score: Mapped[Decimal] = mapped_column(DECIMAL(3, 2), default=1.00)
    
    # Relationships
    rule: Mapped["DetectionRule"] = relationship("DetectionRule", back_populates="ioc_mappings")
    ioc: Mapped["Ioc"] = relationship("Ioc", back_populates="rule_mappings")
    
    __table_args__ = (
        UniqueConstraint('rule_id', 'ioc_id', 'relationship_type', name='unique_rule_ioc_relationship'),
    )
