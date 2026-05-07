"""
Audit API Routes

Endpoints for accessing audit logs and compliance data.
Uses PII-safe storage to prevent sensitive data leakage in logs.
"""

from fastapi import APIRouter, Query, HTTPException, Depends
from typing import List, Dict, Any, Optional
from datetime import datetime

from ..storage.pii_safe_audit import get_pii_safe_audit_store, PIISafeAuditStore
from ..middleware.auth import require_auth, require_scope
from fastapi import Request

router = APIRouter(prefix="/audit", tags=["audit"])


def _get_audit_store() -> PIISafeAuditStore:
    """Dependency to get the PII-safe audit store."""
    return get_pii_safe_audit_store()


@router.get("", response_model=Dict[str, Any])
@router.get("/", response_model=Dict[str, Any])
@require_auth
async def get_audit_logs(
    request: Request,
    limit: Optional[int] = Query(100, description="Maximum number of logs to return"),
    offset: Optional[int] = Query(0, description="Number of logs to skip"),
    action: Optional[str] = Query(None, description="Filter by action type"),
    start_time: Optional[float] = Query(None, description="Start timestamp (unix epoch)"),
    end_time: Optional[float] = Query(None, description="End timestamp (unix epoch)"),
    store: PIISafeAuditStore = Depends(_get_audit_store)
):
    """
    Retrieve audit logs.

    Args:
        limit: Maximum number of logs to return
        offset: Number of logs to skip for pagination
        action: Filter by action type (sanitized, blocked, etc.)
        start_time: Filter by start timestamp
        end_time: Filter by end timestamp

    Returns:
        List of audit log entries (PII-sanitized)
    """
    tenant_id = request.state.tenant_id

    # Convert unix timestamps to datetime
    start_dt = datetime.fromtimestamp(start_time) if start_time else None
    end_dt = datetime.fromtimestamp(end_time) if end_time else None

    logs = store.list_events(
        tenant_id=tenant_id,
        limit=limit or 100,
        offset=offset or 0,
        action_filter=action,
        start_time=start_dt,
        end_time=end_dt
    )

    # Get total count (without pagination)
    all_logs = store.list_events(
        tenant_id=tenant_id,
        limit=10000,
        action_filter=action,
        start_time=start_dt,
        end_time=end_dt
    )
    total = len(all_logs)

    return {
        "total": total,
        "returned": len(logs),
        "offset": offset,
        "limit": limit,
        "logs": logs
    }


@router.get("/stats")
@require_auth
async def get_audit_stats(
    request: Request,
    store: PIISafeAuditStore = Depends(_get_audit_store)
):
    """
    Get summary statistics from audit logs.

    Returns:
        Statistics about PII detection and sanitization (PII-safe)
    """
    tenant_id = request.state.tenant_id
    stats = store.get_stats(tenant_id=tenant_id)

    # Calculate total entities from sanitized data
    all_logs = store.list_events(tenant_id=tenant_id, limit=10000)
    total_entities = sum(len(log.get("entities_found", [])) for log in all_logs)

    return {
        "total_events": stats.get("total_events", 0),
        "total_entities_detected": total_entities,
        "actions": stats.get("actions", {}),
        "risk_scores": stats.get("risk_scores", {})
    }


@router.get("/export")
@require_auth
@require_scope("admin")
async def export_audit_logs(
    request: Request,
    format: Optional[str] = Query("json", description="Export format: json or csv"),
    start_time: Optional[float] = Query(None, description="Start timestamp (unix epoch)"),
    end_time: Optional[float] = Query(None, description="End timestamp (unix epoch)"),
    store: PIISafeAuditStore = Depends(_get_audit_store)
):
    """
    Export audit logs for compliance reporting.

    Args:
        format: Export format (json or csv)
        start_time: Optional start timestamp
        end_time: Optional end timestamp

    Returns:
        Exported audit logs (PII-sanitized)
    """
    tenant_id = request.state.tenant_id

    start_dt = datetime.fromtimestamp(start_time) if start_time else None
    end_dt = datetime.fromtimestamp(end_time) if end_time else None

    content = store.export_events(
        tenant_id=tenant_id,
        format=format,
        start_time=start_dt,
        end_time=end_dt
    )

    return {
        "format": format,
        "content": content,
        "pii_sanitized": True,
        "warning": "Audit logs are PII-sanitized for security"
    }


@router.delete("", status_code=204)
@router.delete("/", status_code=204)
@require_auth
@require_scope("admin")
async def clear_audit_log(
    request: Request,
    older_than_days: Optional[int] = Query(None, description="Only delete logs older than N days"),
    store: PIISafeAuditStore = Depends(_get_audit_store)
):
    """
    Clear audit logs (admin only).

    Args:
        older_than_days: If provided, only delete logs older than this many days

    Returns:
        No content
    """
    tenant_id = request.state.tenant_id

    if older_than_days:
        from datetime import timedelta
        cutoff = datetime.now() - timedelta(days=older_than_days)
        deleted = store.delete_events(tenant_id=tenant_id, older_than=cutoff)
    else:
        # Delete all events for tenant
        deleted = store.delete_events(tenant_id=tenant_id)

    return None
