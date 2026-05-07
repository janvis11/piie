"""
Auth API Routes

Endpoints for managing tenants and API keys.
Uses persistent database storage for tenants and API keys.
"""

from fastapi import APIRouter, HTTPException, status, Depends
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from ..middleware.auth import api_key_manager, tenant_manager, require_auth, require_scope
from ..storage.auth_store import get_auth_store, AuthStore
from ..config import get_auth_config
from fastapi import Request

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
@require_auth
@require_scope("admin")
async def create_tenant(tenant: TenantCreate):
    """
    Create a new tenant.

    Tenants isolate data, policies, and API keys.
    Requires admin scope.
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
@require_auth
@require_scope("admin")
async def list_tenants():
    """List all tenants. Requires admin scope."""
    tenants = tenant_manager.list_tenants()
    return [TenantResponse(**t) for t in tenants]


@router.get("/tenants/{tenant_id}", response_model=TenantResponse)
@require_auth
async def get_tenant(tenant_id: str, request: Request):
    """
    Get a specific tenant by ID.

    Users can only view their own tenant unless they have admin scope.
    """
    current_tenant_id = request.state.tenant_id
    scopes = request.state.scopes

    # Non-admin users can only view their own tenant
    if "admin" not in scopes and tenant_id != current_tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. Can only view own tenant."
        )

    tenant = tenant_manager.get_tenant(tenant_id)
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tenant '{tenant_id}' not found"
        )
    return TenantResponse(**tenant)


@router.post("/api-keys", response_model=APIKeyCreateResponse, status_code=status.HTTP_201_CREATED)
@require_auth
async def create_api_key(request_body: APIKeyCreate, request: Request):
    """
    Create a new API key for a tenant.

    The returned key value is shown only once - store it securely.
    Users can only create keys for their own tenant unless they have admin scope.
    """
    current_tenant_id = request.state.tenant_id
    scopes = request.state.scopes

    # Non-admin users can only create keys for their own tenant
    if "admin" not in scopes and request_body.tenant_id != current_tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. Can only create keys for own tenant."
        )

    tenant = tenant_manager.get_tenant(request_body.tenant_id)
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tenant '{request_body.tenant_id}' not found"
        )

    expires_at = None
    if request_body.expires_in_days:
        import time
        expires_at = time.time() + (request_body.expires_in_days * 24 * 60 * 60)

    key = api_key_manager.create_key(
        tenant_id=request_body.tenant_id,
        name=request_body.name,
        scopes=request_body.scopes,
        expires_at=expires_at
    )

    return APIKeyCreateResponse(
        key=key,
        tenant_id=request_body.tenant_id,
        name=request_body.name,
        scopes=request_body.scopes,
        warning="Store this key securely - it cannot be retrieved again"
    )


@router.get("/tenants/{tenant_id}/api-keys", response_model=List[APIKeyInfo])
@require_auth
async def list_api_keys(tenant_id: str, request: Request):
    """
    List API keys for a tenant (key values not shown for security).

    Users can only view keys for their own tenant unless they have admin scope.
    """
    current_tenant_id = request.state.tenant_id
    scopes = request.state.scopes

    # Non-admin users can only view keys for their own tenant
    if "admin" not in scopes and tenant_id != current_tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. Can only view keys for own tenant."
        )

    tenant = tenant_manager.get_tenant(tenant_id)
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tenant '{tenant_id}' not found"
        )

    keys = api_key_manager.get_keys_for_tenant(tenant_id)
    return [APIKeyInfo(**k) for k in keys]


@router.delete("/api-keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
@require_auth
async def revoke_api_key(key_id: str, request: Request):
    """
    Revoke an API key.

    Requires admin scope or ownership of the key's tenant.
    """
    # This is a simplified implementation
    # A full implementation would look up the key by ID and check ownership
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Key revocation by ID not yet implemented - use the full key path"
    )


@router.post("/api-keys/revoke", status_code=status.HTTP_204_NO_CONTENT)
@require_auth
@require_scope("admin")
async def revoke_api_key_by_value(key: str):
    """
    Revoke an API key by its value.

    Requires admin scope.
    """
    revoked = api_key_manager.revoke_key(key)
    if not revoked:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found"
        )
    return None
