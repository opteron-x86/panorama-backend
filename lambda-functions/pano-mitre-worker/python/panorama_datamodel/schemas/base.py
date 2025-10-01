"""Base schemas and enums"""
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, ConfigDict

class RuleType(str, Enum):
    YARA = "yara"
    SURICATA = "suricata"
    SIGMA = "sigma"
    ELASTIC = "elastic"
    SENTINEL = "sentinel"
    TCL = "tcl"

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class IocType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    EMAIL = "email"

class BaseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

class TimestampSchema(BaseSchema):
    created_date: datetime
    updated_date: datetime