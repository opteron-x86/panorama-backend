"""Detection rules schemas"""
import json
from datetime import datetime
from typing import List, Optional, Dict, Any
from decimal import Decimal

from pydantic import Field, ConfigDict

from .base import BaseSchema, TimestampSchema, RuleType, Severity
from .mitre import MitreTechnique
from .vulnerabilities import CveEntry

class RuleSource(BaseSchema):
    id: int
    name: str
    source_type: str
    is_active: bool = True

class DetectionRule(BaseSchema):
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    rule_id: str
    name: str
    description: Optional[str] = None
    rule_content: Optional[str] = None
    rule_type: RuleType
    severity: Optional[Severity] = None
    confidence_score: Optional[float] = None
    is_active: bool = True
    tags: Optional[List[str]] = None
    created_date: Optional[datetime] = None
    updated_date: Optional[datetime] = None
    hash: Optional[str] = None
    
    # Relationships
    source: Optional[RuleSource] = None
    mitre_techniques: List[str] = []
    cves: List[str] = []
    
    # Details (only populated when requested)
    mitre_details: Optional[List[Dict[str, Any]]] = None
    cve_details: Optional[List[Dict[str, Any]]] = None

class RuleCreateRequest(BaseSchema):
    rule_id: str
    source_id: int
    name: str
    description: Optional[str] = None
    rule_content: str
    rule_type: RuleType
    severity: Optional[Severity] = None
    tags: Optional[List[str]] = None

class RuleSearchParams(BaseSchema):
    query: Optional[str] = None
    rule_types: Optional[List[RuleType]] = None
    severities: Optional[List[Severity]] = None
    source_ids: Optional[List[int]] = None
    tags: Optional[List[str]] = None
    is_active: Optional[bool] = None
    mitre_techniques: Optional[List[str]] = None
    cve_ids: Optional[List[str]] = None
    offset: int = Field(0, ge=0)
    limit: int = Field(25, ge=1, le=1000)
    sort_by: str = 'updated_date'
    sort_dir: str = 'desc'
    include_stats: bool = False
