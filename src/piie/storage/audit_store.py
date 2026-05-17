"""
Supabase-backed audit event store.

Provides persistent storage for compliance and governance tracking.
"""

import json
import uuid
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from .models import AuditEvent
from .database import get_supabase


class AuditStore:
    """
    Supabase-backed audit event store.
    """

    def __init__(self):
        """Initialize the audit store."""
        self._client = get_supabase()

    def record_event(
        self,
        tenant_id: str,
        trace_id: str,
        action: str,
        entities_found: Optional[List[Dict]] = None,
        risk_score: Optional[float] = None,
        policy_id: Optional[str] = None,
        request_path: Optional[str] = None,
        request_method: Optional[str] = None,
        transformations: Optional[List[Dict]] = None,
        metadata: Optional[Dict] = None
    ) -> str:
        """
        Record an audit event.

        Args:
            tenant_id: Tenant identifier
            trace_id: Request trace ID
            action: Event action (sanitized, blocked, allowed)
            entities_found: List of detected PII entities
            risk_score: Calculated risk score
            policy_id: Policy that was applied
            request_path: Request path
            request_method: HTTP method
            transformations: List of transformations applied
            metadata: Additional metadata

        Returns:
            Event ID
        """
        event_id = f"event_{uuid.uuid4().hex[:12]}"

        event_data = {
            "event_id": event_id,
            "tenant_id": tenant_id,
            "trace_id": trace_id,
            "action": action,
            "entities_found": json.dumps(entities_found) if entities_found else None,
            "risk_score": risk_score,
            "policy_id": policy_id,
            "request_path": request_path,
            "request_method": request_method,
            "transformations": json.dumps(transformations) if transformations else None,
            "metadata_json": json.dumps(metadata) if metadata else None
        }

        response = self._client.table("audit_events").insert(event_data).execute()

        if response.data:
            return event_id
        raise Exception("Failed to record audit event")

    def get_event(self, event_id: str, tenant_id: Optional[str] = None) -> Optional[Dict]:
        """
        Get a single audit event by ID.

        Args:
            event_id: Event ID
            tenant_id: Optional tenant ID for isolation

        Returns:
            Event as dictionary if found
        """
        response = self._client.table("audit_events").select("*").eq("event_id", event_id).execute()

        if not response.data:
            return None

        event_data = response.data[0]

        if tenant_id and event_data.get("tenant_id") != tenant_id:
            return None  # Tenant isolation

        return self._event_to_dict(event_data)

    def list_events(
        self,
        tenant_id: str,
        limit: int = 100,
        offset: int = 0,
        action_filter: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        policy_id: Optional[str] = None
    ) -> List[Dict]:
        """
        List audit events for a tenant with filtering.

        Args:
            tenant_id: Tenant ID to filter by
            limit: Maximum events to return
            offset: Number of events to skip
            action_filter: Filter by action type
            start_time: Filter by start timestamp
            end_time: Filter by end timestamp
            policy_id: Filter by policy ID

        Returns:
            List of events as dictionaries
        """
        query = self._client.table("audit_events").select("*").eq("tenant_id", tenant_id)

        if action_filter:
            query = query.eq("action", action_filter)

        if start_time:
            query = query.gte("timestamp", start_time.isoformat())

        if end_time:
            query = query.lte("timestamp", end_time.isoformat())

        if policy_id:
            query = query.eq("policy_id", policy_id)

        # Order by timestamp descending (newest first)
        query = query.order("timestamp", desc=True)
        query = query.range(offset, offset + limit - 1)

        response = query.execute()
        return [self._event_to_dict(e) for e in response.data]

    def get_stats(
        self,
        tenant_id: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Get summary statistics for audit events.

        Args:
            tenant_id: Tenant ID
            start_time: Optional start time filter
            end_time: Optional end time filter

        Returns:
            Statistics dictionary
        """
        # Base query
        query = self._client.table("audit_events").select("*").eq("tenant_id", tenant_id)

        if start_time:
            query = query.gte("timestamp", start_time.isoformat())
        if end_time:
            query = query.lte("timestamp", end_time.isoformat())

        response = query.execute()
        events = response.data

        # Total count
        total = len(events)

        # Count by action
        actions: Dict[str, int] = {}
        for event in events:
            action = event.get("action", "unknown")
            actions[action] = actions.get(action, 0) + 1

        # Risk score stats
        risk_scores = [e.get("risk_score") for e in events if e.get("risk_score") is not None]
        risk_stats = {
            "average": sum(risk_scores) / len(risk_scores) if risk_scores else 0,
            "max": max(risk_scores) if risk_scores else 0,
            "min": min(risk_scores) if risk_scores else 0
        }

        return {
            "total_events": total,
            "actions": actions,
            "risk_scores": risk_stats,
            "period": {
                "start": start_time.isoformat() if start_time else None,
                "end": end_time.isoformat() if end_time else None
            }
        }

    def export_events(
        self,
        tenant_id: str,
        format: str = "json",
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> str:
        """
        Export audit events for compliance reporting.

        Args:
            tenant_id: Tenant ID
            format: Export format (json or csv)
            start_time: Optional start time
            end_time: Optional end time

        Returns:
            Exported data as string
        """
        events = self.list_events(
            tenant_id=tenant_id,
            limit=10000,
            start_time=start_time,
            end_time=end_time
        )

        if format == "csv":
            import csv
            import io

            output = io.StringIO()
            if events:
                fieldnames = list(events[0].keys())
                writer = csv.DictWriter(output, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(events)
            else:
                output.write("No audit events found\n")

            return output.getvalue()

        # Default: JSON
        return json.dumps(events, indent=2)

    def delete_events(
        self,
        tenant_id: str,
        older_than: Optional[datetime] = None
    ) -> int:
        """
        Delete audit events (for retention policies).

        Args:
            tenant_id: Tenant ID
            older_than: Delete events older than this timestamp

        Returns:
            Number of events deleted
        """
        query = self._client.table("audit_events").delete().eq("tenant_id", tenant_id)

        if older_than:
            query = query.lt("timestamp", older_than.isoformat())

        response = query.execute()
        return len(response.data) if response.data else 0

    def _event_to_dict(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Convert event data to dictionary."""
        return {
            "event_id": event.get("event_id", ""),
            "tenant_id": event.get("tenant_id", ""),
            "trace_id": event.get("trace_id", ""),
            "action": event.get("action", ""),
            "entities_found": json.loads(event.get("entities_found", "[]")) if event.get("entities_found") else [],
            "risk_score": event.get("risk_score"),
            "policy_id": event.get("policy_id"),
            "request_path": event.get("request_path"),
            "request_method": event.get("request_method"),
            "transformations": json.loads(event.get("transformations", "[]")) if event.get("transformations") else [],
            "metadata": json.loads(event.get("metadata_json", "{}")) if event.get("metadata_json") else {},
            "timestamp": event.get("timestamp")
        }


# Global instance
_audit_store: Optional[AuditStore] = None


def get_audit_store() -> AuditStore:
    """Get or create the global audit store instance."""
    global _audit_store
    if _audit_store is None:
        _audit_store = AuditStore()
    return _audit_store


def init_audit_store() -> AuditStore:
    """Initialize the global audit store."""
    global _audit_store
    _audit_store = AuditStore()
    return _audit_store


class InMemoryAuditStore:
    """
    In-memory audit store for testing.

    Provides the same interface as AuditStore but stores data in memory.
    """

    def __init__(self):
        """Initialize the in-memory audit store."""
        self._events: List[Dict[str, Any]] = []

    def record_event(
        self,
        tenant_id: str,
        trace_id: str,
        action: str,
        entities_found: Optional[List[Dict]] = None,
        risk_score: Optional[float] = None,
        policy_id: Optional[str] = None,
        request_path: Optional[str] = None,
        request_method: Optional[str] = None,
        transformations: Optional[List[Dict]] = None,
        metadata: Optional[Dict] = None
    ) -> str:
        """Record an audit event in memory."""
        import uuid
        event_id = f"event_{uuid.uuid4().hex[:12]}"

        event_data = {
            "event_id": event_id,
            "tenant_id": tenant_id,
            "trace_id": trace_id,
            "action": action,
            "entities_found": entities_found or [],
            "risk_score": risk_score,
            "policy_id": policy_id,
            "request_path": request_path,
            "request_method": request_method,
            "transformations": transformations or [],
            "metadata": metadata or {},
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        self._events.append(event_data)
        return event_id

    def get_event(self, event_id: str, tenant_id: Optional[str] = None) -> Optional[Dict]:
        """Get a single audit event by ID."""
        for event in self._events:
            if event["event_id"] == event_id:
                if tenant_id is None or event["tenant_id"] == tenant_id:
                    return event
        return None

    def list_events(
        self,
        tenant_id: str,
        limit: int = 100,
        offset: int = 0,
        action_filter: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        policy_id: Optional[str] = None
    ) -> List[Dict]:
        """List audit events for a tenant with filtering."""
        # Filter by tenant
        filtered = [e for e in self._events if e["tenant_id"] == tenant_id]

        # Apply action filter
        if action_filter:
            filtered = [e for e in filtered if e["action"] == action_filter]

        # Apply policy filter
        if policy_id:
            filtered = [e for e in filtered if e["policy_id"] == policy_id]

        # Apply time filters
        if start_time:
            filtered = [e for e in filtered if e["timestamp"] >= start_time.isoformat()]
        if end_time:
            filtered = [e for e in filtered if e["timestamp"] <= end_time.isoformat()]

        # Sort by timestamp descending
        filtered.sort(key=lambda x: x["timestamp"], reverse=True)

        # Apply pagination
        return filtered[offset:offset + limit]

    def get_stats(
        self,
        tenant_id: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Get summary statistics for audit events."""
        events = self.list_events(tenant_id, limit=10000, start_time=start_time, end_time=end_time)

        total = len(events)

        # Count by action
        actions: Dict[str, int] = {}
        for event in events:
            action = event.get("action", "unknown")
            actions[action] = actions.get(action, 0) + 1

        # Risk score stats
        risk_scores = [e.get("risk_score") for e in events if e.get("risk_score") is not None]
        risk_stats = {
            "average": sum(risk_scores) / len(risk_scores) if risk_scores else 0,
            "max": max(risk_scores) if risk_scores else 0,
            "min": min(risk_scores) if risk_scores else 0
        }

        # Count total entities
        total_entities = sum(len(e.get("entities_found", [])) for e in events)

        return {
            "total_events": total,
            "total_entities_detected": total_entities,
            "actions": actions,
            "risk_scores": risk_stats,
            "period": {
                "start": start_time.isoformat() if start_time else None,
                "end": end_time.isoformat() if end_time else None
            }
        }

    def export_events(
        self,
        tenant_id: str,
        format: str = "json",
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> str:
        """Export audit events for compliance reporting."""
        events = self.list_events(
            tenant_id=tenant_id,
            limit=10000,
            start_time=start_time,
            end_time=end_time
        )

        if format == "csv":
            import csv
            import io

            output = io.StringIO()
            if events:
                fieldnames = list(events[0].keys())
                writer = csv.DictWriter(output, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(events)
            else:
                output.write("No audit events found\n")

            return output.getvalue()

        # Default: JSON
        return json.dumps(events, indent=2)

    def delete_events(
        self,
        tenant_id: str,
        older_than: Optional[datetime] = None
    ) -> int:
        """Delete audit events (for retention policies)."""
        original_count = len(self._events)

        if older_than is None:
            # Delete all events for tenant
            self._events = [e for e in self._events if e["tenant_id"] != tenant_id]
        else:
            # Delete events older than timestamp
            cutoff = older_than.isoformat()
            self._events = [e for e in self._events if e["tenant_id"] != tenant_id or e["timestamp"] >= cutoff]

        return original_count - len(self._events)
