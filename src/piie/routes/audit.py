"""
Audit API Routes

Endpoints for accessing audit logs and compliance data.
"""

from fastapi import APIRouter, Query, HTTPException
from typing import List, Dict, Any, Optional
from datetime import datetime
import time

from storage.audit_store import get_audit_store

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("", response_model=Dict[str, Any])
@router.get("/", response_model=Dict[str, Any])
async def get_audit_logs(
    limit: Optional[int] = Query(100, description="Maximum number of logs to return"),
    offset: Optional[int] = Query(0, description="Number of logs to skip"),
    action: Optional[str] = Query(None, description="Filter by action type"),
    start_time: Optional[float] = Query(None, description="Start timestamp (unix epoch)"),
    end_time: Optional[float] = Query(None, description="End timestamp (unix epoch)")
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
        List of audit log entries
    """
    try:
        audit_store = get_audit_store()

        # Convert unix timestamps to datetime
        start_dt = datetime.fromtimestamp(start_time) if start_time else None
        end_dt = datetime.fromtimestamp(end_time) if end_time else None

        # For now, query without tenant filter (would require auth context)
        events = audit_store.list_events(
            tenant_id="default",
            limit=limit or 100,
            offset=offset,
            action_filter=action,
            start_time=start_dt,
            end_time=end_dt
        )

        return {
            "total": len(events),
            "returned": len(events),
            "offset": offset,
            "limit": limit,
            "logs": events
        }
    except Exception as e:
        return {
            "total": 0,
            "returned": 0,
            "offset": offset,
            "limit": limit,
            "logs": [],
            "error": str(e)
        }


@router.get("/stats")
async def get_audit_stats():
    """
    Get summary statistics from audit logs.

    Returns:
        Statistics about PII detection and sanitization
    """
    try:
        audit_store = get_audit_store()
        stats = audit_store.get_stats(tenant_id="default")
        return stats
    except Exception as e:
        return {
            "total_events": 0,
            "total_entities_detected": 0,
            "actions": {},
            "risk_scores": {
                "average": 0,
                "max": 0,
                "min": 0
            },
            "error": str(e)
        }


@router.get("/export")
async def export_audit_logs(
    format: Optional[str] = Query("json", description="Export format: json or csv")
):
    """
    Export audit logs for compliance reporting.

    Args:
        format: Export format (json or csv)

    Returns:
        Exported audit logs
    """
    try:
        audit_store = get_audit_store()
        content = audit_store.export_events(
            tenant_id="default",
            format=format or "json"
        )

        if format == "csv":
            return {
                "format": "csv",
                "content": content
            }

        return {
            "format": "json",
            "count": len(audit_store.list_events(tenant_id="default", limit=10000)),
            "logs": content
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("", status_code=204)
@router.delete("/", status_code=204)
async def clear_audit_log():
    """
    Clear all audit logs.

    Use with caution - this is typically only for testing.
    """
    _audit_log.clear()
    return None
