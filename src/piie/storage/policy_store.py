"""
Supabase-backed policy store.

Provides persistent storage for privacy policies with tenant isolation.
"""

import json
import uuid
from typing import List, Dict, Any, Optional
from .models import Policy
from .database import get_supabase


class PolicyStore:
    """
    Supabase-backed policy store with tenant isolation.
    """

    def __init__(self):
        """Initialize the policy store."""
        self._client = get_supabase()

    def create_policy(
        self,
        tenant_id: str,
        name: str,
        entity_types: List[str],
        action: str,
        description: Optional[str] = None
    ) -> Policy:
        """
        Create a new policy.

        Args:
            tenant_id: Owner tenant ID
            name: Policy name
            entity_types: List of entity types this policy applies to
            action: Action to take (allow, redact, pseudonymize, block)
            description: Optional policy description

        Returns:
            Created Policy object
        """
        policy_id = f"policy_{uuid.uuid4().hex[:12]}"

        policy_data = {
            "policy_id": policy_id,
            "tenant_id": tenant_id,
            "name": name,
            "entity_types": json.dumps(entity_types),
            "action": action.lower(),
            "description": description
        }

        response = self._client.table("policies").insert(policy_data).execute()

        if response.data:
            return self._dict_to_policy(response.data[0])
        raise Exception("Failed to create policy")

    def get_policy(self, policy_id: str, tenant_id: Optional[str] = None) -> Optional[Policy]:
        """
        Get a policy by ID.

        Args:
            policy_id: Policy ID
            tenant_id: Optional tenant ID for isolation check

        Returns:
            Policy if found and accessible, None otherwise
        """
        response = self._client.table("policies").select("*").eq("policy_id", policy_id).execute()

        if not response.data:
            return None

        policy = self._dict_to_policy(response.data[0])

        if tenant_id and policy.tenant_id != tenant_id:
            return None  # Tenant isolation

        return policy

    def list_policies(self, tenant_id: str, active_only: bool = True) -> List[Policy]:
        """
        List all policies for a tenant.

        Args:
            tenant_id: Tenant ID to filter by
            active_only: If True, only return active policies

        Returns:
            List of policies
        """
        query = self._client.table("policies").select("*").eq("tenant_id", tenant_id)

        if active_only:
            query = query.eq("active", True)

        response = query.execute()
        return [self._dict_to_policy(p) for p in response.data]

    def update_policy(
        self,
        policy_id: str,
        tenant_id: str,
        name: Optional[str] = None,
        entity_types: Optional[List[str]] = None,
        action: Optional[str] = None,
        description: Optional[str] = None
    ) -> Optional[Policy]:
        """
        Update an existing policy.

        Args:
            policy_id: Policy ID to update
            tenant_id: Tenant ID for isolation check
            name: New name (optional)
            entity_types: New entity types (optional)
            action: New action (optional)
            description: New description (optional)

        Returns:
            Updated Policy if found, None otherwise
        """
        # First check if policy exists and belongs to tenant
        existing = self.get_policy(policy_id, tenant_id)
        if not existing:
            return None

        update_data = {}
        if name:
            update_data["name"] = name
        if entity_types:
            update_data["entity_types"] = json.dumps(entity_types)
        if action:
            update_data["action"] = action.lower()
        if description:
            update_data["description"] = description

        response = self._client.table("policies").update(update_data).eq("policy_id", policy_id).execute()

        if response.data:
            return self._dict_to_policy(response.data[0])
        return None

    def delete_policy(self, policy_id: str, tenant_id: str) -> bool:
        """
        Delete a policy.

        Args:
            policy_id: Policy ID to delete
            tenant_id: Tenant ID for isolation check

        Returns:
            True if deleted, False if not found
        """
        # First check if policy exists and belongs to tenant
        existing = self.get_policy(policy_id, tenant_id)
        if not existing:
            return False

        response = self._client.table("policies").delete().eq("policy_id", policy_id).execute()
        return len(response.data) > 0

    def deactivate_policy(self, policy_id: str, tenant_id: str) -> bool:
        """
        Deactivate a policy without deleting it.

        Args:
            policy_id: Policy ID
            tenant_id: Tenant ID for isolation check

        Returns:
            True if deactivated, False if not found
        """
        existing = self.get_policy(policy_id, tenant_id)
        if not existing:
            return False

        response = self._client.table("policies").update({"active": False}).eq("policy_id", policy_id).execute()
        return len(response.data) > 0

    def policy_to_dict(self, policy: Policy) -> Dict[str, Any]:
        """Convert a Policy object to dictionary."""
        return {
            "policy_id": policy.policy_id,
            "tenant_id": policy.tenant_id,
            "name": policy.name,
            "entity_types": json.loads(policy.entity_types),
            "action": policy.action,
            "description": policy.description,
            "version": policy.version,
            "active": policy.active,
            "created_at": str(policy.created_at) if policy.created_at else None,
            "updated_at": str(policy.updated_at) if policy.updated_at else None
        }

    def _dict_to_policy(self, data: Dict[str, Any]) -> Policy:
        """Convert dictionary to Policy object."""
        return Policy(
            policy_id=data.get("policy_id", ""),
            tenant_id=data.get("tenant_id", ""),
            name=data.get("name", ""),
            entity_types=data.get("entity_types", "[]"),
            action=data.get("action", ""),
            description=data.get("description"),
            version=data.get("version", "1.0.0"),
            active=data.get("active", True),
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at")
        )


# Global instance
_policy_store: Optional[PolicyStore] = None


def get_policy_store() -> PolicyStore:
    """Get or create the global policy store instance."""
    global _policy_store
    if _policy_store is None:
        _policy_store = PolicyStore()
    return _policy_store


def init_policy_store() -> PolicyStore:
    """Initialize the global policy store."""
    global _policy_store
    _policy_store = PolicyStore()
    return _policy_store
