"""
Data models for PII-Safe storage.

Defines data classes for policies, audit events, tenants, and token mappings.
These are used with Supabase client operations.
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from datetime import datetime


@dataclass
class Tenant:
    """Tenant model for multi-tenant isolation."""
    tenant_id: str
    name: str
    metadata_json: Optional[Dict[str, Any]] = None
    active: bool = True
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


@dataclass
class Policy:
    """Policy model for storing privacy policies."""
    policy_id: str
    tenant_id: str
    name: str
    entity_types: str  # JSON array of entity types
    action: str
    description: Optional[str] = None
    version: str = "1.0.0"
    active: bool = True
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


@dataclass
class AuditEvent:
    """Audit event model for compliance tracking."""
    event_id: str
    tenant_id: str
    trace_id: str
    action: str  # sanitized, blocked, allowed
    entities_found: Optional[str] = None  # JSON array of detected entities
    risk_score: Optional[float] = None
    policy_id: Optional[str] = None
    request_path: Optional[str] = None
    request_method: Optional[str] = None
    transformations: Optional[str] = None  # JSON array of transformations
    metadata_json: Optional[str] = None  # Additional metadata
    timestamp: Optional[datetime] = None


@dataclass
class TokenMapping:
    """Token mapping model for pseudonymization."""
    id: str
    tenant_id: str
    original_hash: str
    token: str
    entity_type: str
    namespace: str = "default"
    expires_at: Optional[datetime] = None
    created_at: Optional[datetime] = None


@dataclass
class APIKey:
    """API key model for service authentication."""
    key_hash: str
    tenant_id: str
    name: str
    scopes: str  # JSON array of scopes
    active: bool = True
    created_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None
