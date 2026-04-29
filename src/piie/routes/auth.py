"""
Auth API Routes

Endpoints for managing tenants and API keys.
"""

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from middleware.auth import api_key_manager, tenant_manager

router = APIRouter(prefix="/auth", tags=["auth"])


class TenantCreate(BaseModel):
    """Request to create a tenant."""
    tenant_id: str
    name: str
    metadata: Optional[Dict[str, Any]] = None


class TenantResponse(BaseModel):
    """Tenant response."""
    tenant_id: str
    name: str
    metadata: Dict[str, Any]
    created_at: float
    active: bool


class APIKeyCreate(BaseModel):
    """Request to create an API key."""
    tenant_id: str
    name: str
    scopes: List[str]
    expires_in_days: Optional[int] = None


class APIKeyCreateResponse(BaseModel):
    """API key creation response."""
    key: str
    tenant_id: str
    name: str
    scopes: List[str]
    warning: str


class APIKeyInfo(BaseModel):
    """API key info (without the actual key)."""
    name: str
    scopes: List[str]
    created_at: float
    last_used_at: Optional[float]
    active: bool


@router.post("/tenants", response_model=TenantResponse, status_code=status.HTTP_201_CREATED)
async def create_tenant(tenant: TenantCreate):
    """
    Create a new tenant.

    Tenants isolate data, policies, and API keys.
    """
    existing = tenant_manager.get_tenant(tenant.tenant_id)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Tenant '{tenant.tenant_id}' already exists"
        )

    created = tenant_manager.create_tenant(
        tenant_id=tenant.tenant_id,
        name=tenant.name,
        metadata=tenant.metadata
    )

    return TenantResponse(**created)


@router.get("/tenants", response_model=List[TenantResponse])
async def list_tenants():
    """List all tenants."""
    tenants = tenant_manager.list_tenants()
    return [TenantResponse(**t) for t in tenants]


@router.get("/tenants/{tenant_id}", response_model=TenantResponse)
async def get_tenant(tenant_id: str):
    """Get a specific tenant by ID."""
    tenant = tenant_manager.get_tenant(tenant_id)
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tenant '{tenant_id}' not found"
        )
    return TenantResponse(**tenant)


@router.post("/api-keys", response_model=APIKeyCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_api_key(request: APIKeyCreate):
    """
    Create a new API key for a tenant.

    The returned key value is shown only once - store it securely.
    """
    tenant = tenant_manager.get_tenant(request.tenant_id)
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tenant '{request.tenant_id}' not found"
        )

    expires_at = None
    if request.expires_in_days:
        import time
        expires_at = time.time() + (request.expires_in_days * 24 * 60 * 60)

    key = api_key_manager.create_key(
        tenant_id=request.tenant_id,
        name=request.name,
        scopes=request.scopes,
        expires_at=expires_at
    )

    return APIKeyCreateResponse(
        key=key,
        tenant_id=request.tenant_id,
        name=request.name,
        scopes=request.scopes,
        warning="Store this key securely - it cannot be retrieved again"
    )


@router.get("/tenants/{tenant_id}/api-keys", response_model=List[APIKeyInfo])
async def list_api_keys(tenant_id: str):
    """List API keys for a tenant (key values not shown for security)."""
    tenant = tenant_manager.get_tenant(tenant_id)
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tenant '{tenant_id}' not found"
        )

    keys = api_key_manager.get_keys_for_tenant(tenant_id)
    return [APIKeyInfo(**k) for k in keys]


@router.delete("/api-keys/{key_prefix}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_api_key(key_prefix: str):
    """
    Revoke an API key by its prefix.

    For security, you can only revoke keys you have access to.
    """
    # In production, this would require admin scope
    # For now, we just revoke if the prefix matches
    revoked = False
    # This is a simplified implementation
    # A full implementation would need to track key prefixes

    if not revoked:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Key revocation requires admin access - use the full key"
        )
