"""
Database-backed storage for tenants and API keys.

Provides persistent storage for authentication and tenant isolation.
"""

import json
import hashlib
import secrets
import time
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
from .models import Tenant, APIKey
from .database import get_supabase


class AuthStore:
    """
    Database-backed store for tenants and API keys.

    Replaces in-memory storage with persistent Supabase-backed storage.
    """

    def __init__(self):
        """Initialize the auth store."""
        self._client = get_supabase()

    # ==================== Tenant Operations ====================

    def create_tenant(
        self,
        tenant_id: str,
        name: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Tenant:
        """
        Create a new tenant.

        Args:
            tenant_id: Unique tenant identifier
            name: Human-readable tenant name
            metadata: Optional metadata dictionary

        Returns:
            Created Tenant object

        Raises:
            Exception: If tenant already exists or database error
        """
        tenant_data = {
            "tenant_id": tenant_id,
            "name": name,
            "metadata_json": json.dumps(metadata) if metadata else None,
            "active": True
        }

        response = self._client.table("tenants").insert(tenant_data).execute()

        if not response.data:
            raise Exception(f"Failed to create tenant '{tenant_id}'")

        return self._tenant_to_model(response.data[0])

    def get_tenant(self, tenant_id: str) -> Optional[Tenant]:
        """
        Get tenant by ID.

        Args:
            tenant_id: Tenant identifier

        Returns:
            Tenant object if found, None otherwise
        """
        response = self._client.table("tenants").select("*").eq("tenant_id", tenant_id).execute()

        if not response.data:
            return None

        return self._tenant_to_model(response.data[0])

    def list_tenants(self) -> List[Tenant]:
        """
        List all tenants.

        Returns:
            List of Tenant objects
        """
        response = self._client.table("tenants").select("*").execute()
        return [self._tenant_to_model(t) for t in response.data]

    def update_tenant(
        self,
        tenant_id: str,
        name: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        active: Optional[bool] = None
    ) -> Optional[Tenant]:
        """
        Update tenant attributes.

        Args:
            tenant_id: Tenant identifier
            name: New name (optional)
            metadata: New metadata (optional)
            active: New active status (optional)

        Returns:
            Updated Tenant object if found, None otherwise
        """
        update_data = {}
        if name is not None:
            update_data["name"] = name
        if metadata is not None:
            update_data["metadata_json"] = json.dumps(metadata)
        if active is not None:
            update_data["active"] = active

        if not update_data:
            return self.get_tenant(tenant_id)

        response = self._client.table("tenants").update(update_data).eq("tenant_id", tenant_id).execute()

        if not response.data:
            return None

        return self._tenant_to_model(response.data[0])

    def delete_tenant(self, tenant_id: str) -> bool:
        """
        Delete a tenant and all associated API keys.

        Args:
            tenant_id: Tenant identifier

        Returns:
            True if deleted, False if not found
        """
        # Delete associated API keys first
        self._client.table("api_keys").delete().eq("tenant_id", tenant_id).execute()

        # Delete tenant
        response = self._client.table("tenants").delete().eq("tenant_id", tenant_id).execute()
        return bool(response.data)

    # ==================== API Key Operations ====================

    def create_key(
        self,
        tenant_id: str,
        name: str,
        scopes: List[str],
        expires_at: Optional[float] = None
    ) -> str:
        """
        Create a new API key.

        Args:
            tenant_id: Tenant identifier
            name: Human-readable key name
            scopes: List of permission scopes
            expires_at: Optional expiration timestamp

        Returns:
            The raw API key value (shown only once)

        Raises:
            Exception: If tenant not found or database error
        """
        # Verify tenant exists
        tenant = self.get_tenant(tenant_id)
        if not tenant:
            raise Exception(f"Tenant '{tenant_id}' not found")

        # Generate secure key
        key = secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(key.encode()).hexdigest()

        key_data = {
            "key_hash": key_hash,
            "tenant_id": tenant_id,
            "name": name,
            "scopes": json.dumps(scopes),
            "active": True,
            "expires_at": datetime.fromtimestamp(expires_at, tz=timezone.utc).isoformat() if expires_at else None
        }

        response = self._client.table("api_keys").insert(key_data).execute()

        if not response.data:
            raise Exception("Failed to create API key")

        # Return raw key (only shown once)
        return key

    def validate_key(self, key: str) -> Optional[Dict[str, Any]]:
        """
        Validate an API key and return metadata if valid.

        Args:
            key: Raw API key value

        Returns:
            Key metadata dictionary if valid, None otherwise
        """
        key_hash = hashlib.sha256(key.encode()).hexdigest()

        response = self._client.table("api_keys").select("*").eq("key_hash", key_hash).execute()

        if not response.data:
            return None

        key_data = response.data[0]

        # Check if active
        if not key_data.get("active", True):
            return None

        # Check expiration
        expires_at = key_data.get("expires_at")
        if expires_at:
            try:
                expiry = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
                if datetime.now(timezone.utc) > expiry:
                    # Mark as inactive
                    self._client.table("api_keys").update({"active": False}).eq("key_hash", key_hash).execute()
                    return None
            except (ValueError, TypeError):
                pass

        # Update last_used_at
        self._client.table("api_keys").update({
            "last_used_at": datetime.now(timezone.utc).isoformat()
        }).eq("key_hash", key_hash).execute()

        # Build metadata
        scopes_raw = key_data.get("scopes", "[]")
        try:
            scopes = json.loads(scopes_raw) if isinstance(scopes_raw, str) else scopes_raw
        except (json.JSONDecodeError, TypeError):
            scopes = []

        return {
            "tenant_id": key_data.get("tenant_id"),
            "name": key_data.get("name"),
            "scopes": scopes,
            "created_at": key_data.get("created_at"),
            "last_used_at": key_data.get("last_used_at"),
            "active": key_data.get("active", True)
        }

    def revoke_key(self, key: str) -> bool:
        """
        Revoke an API key.

        Args:
            key: Raw API key value

        Returns:
            True if revoked, False if not found
        """
        key_hash = hashlib.sha256(key.encode()).hexdigest()

        response = self._client.table("api_keys").update({"active": False}).eq("key_hash", key_hash).execute()
        return bool(response.data)

    def get_keys_for_tenant(self, tenant_id: str) -> List[Dict[str, Any]]:
        """
        Get all API keys for a tenant (without key values).

        Args:
            tenant_id: Tenant identifier

        Returns:
            List of key metadata dictionaries
        """
        response = self._client.table("api_keys").select(
            "name,scopes,active,created_at,expires_at,last_used_at"
        ).eq("tenant_id", tenant_id).execute()

        result = []
        for key_data in response.data:
            scopes_raw = key_data.get("scopes", "[]")
            try:
                scopes = json.loads(scopes_raw) if isinstance(scopes_raw, str) else scopes_raw
            except (json.JSONDecodeError, TypeError):
                scopes = []

            # Convert ISO timestamps to Unix timestamps for API compatibility
            created_at = key_data.get("created_at")
            if created_at:
                try:
                    created_at = datetime.fromisoformat(created_at.replace('Z', '+00:00')).timestamp()
                except (ValueError, TypeError):
                    created_at = None

            last_used_at = key_data.get("last_used_at")
            if last_used_at:
                try:
                    last_used_at = datetime.fromisoformat(last_used_at.replace('Z', '+00:00')).timestamp()
                except (ValueError, TypeError):
                    last_used_at = None

            result.append({
                "name": key_data.get("name"),
                "scopes": scopes,
                "created_at": created_at,
                "last_used_at": last_used_at,
                "active": key_data.get("active", True)
            })

        return result

    def delete_keys_for_tenant(self, tenant_id: str) -> int:
        """
        Delete all API keys for a tenant.

        Args:
            tenant_id: Tenant identifier

        Returns:
            Number of keys deleted
        """
        response = self._client.table("api_keys").delete().eq("tenant_id", tenant_id).execute()
        return len(response.data) if response.data else 0

    # ==================== Utility Methods ====================

    def _tenant_to_model(self, data: Dict[str, Any]) -> Tenant:
        """Convert database row to Tenant model."""
        metadata_raw = data.get("metadata_json")
        try:
            metadata = json.loads(metadata_raw) if metadata_raw else None
        except (json.JSONDecodeError, TypeError):
            metadata = None

        # Convert ISO timestamps to datetime
        created_at = data.get("created_at")
        if created_at:
            try:
                created_at = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
            except (ValueError, TypeError):
                created_at = None

        updated_at = data.get("updated_at")
        if updated_at:
            try:
                updated_at = datetime.fromisoformat(updated_at.replace('Z', '+00:00'))
            except (ValueError, TypeError):
                updated_at = None

        return Tenant(
            tenant_id=data.get("tenant_id", ""),
            name=data.get("name", ""),
            metadata_json=metadata,
            active=data.get("active", True),
            created_at=created_at,
            updated_at=updated_at
        )


# Global instance
_auth_store: Optional[AuthStore] = None


def get_auth_store() -> AuthStore:
    """Get or create the global auth store instance."""
    global _auth_store
    if _auth_store is None:
        _auth_store = AuthStore()
    return _auth_store


def init_auth_store() -> AuthStore:
    """Initialize the global auth store."""
    global _auth_store
    _auth_store = AuthStore()
    return _auth_store
