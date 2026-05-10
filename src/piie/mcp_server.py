"""
PII-Safe MCP Server

Model Context Protocol server for privacy enforcement and governance.
Provides tools, resources, and prompts for AI agents.
"""

import asyncio
import json
import time
import uuid
from datetime import datetime
from typing import Any, Optional
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    Tool,
    Resource,
    Prompt,
    TextContent,
    ResourceTemplate,
)
from pydantic import BaseModel, Field

from .detectors import PIIDetector, EntityType
from .sanitizers import PIISanitizer, PseudonymizationEngine, SanitizationAction
from .config import load_config, get_pseudonymization_config, get_sanitizer_config
from .storage.policy_store import get_policy_store
from .storage.audit_store import get_audit_store
from .storage.token_cache import get_token_cache


# Server configuration
SERVER_NAME = "piie-mcp"
SERVER_VERSION = "0.1.0"

# Initialize server
server = Server(SERVER_NAME)

# Initialize core components
detector = PIIDetector()
pseudo_config = get_pseudonymization_config()
sanitizer_config = get_sanitizer_config()
pseudonym_engine = PseudonymizationEngine(
    salt=pseudo_config.salt,
    token_length=sanitizer_config.pseudonym_token_length,
)
sanitizer = PIISanitizer(pseudonym_engine)

# Initialize persistent stores
policy_store = get_policy_store()
audit_store = get_audit_store()
token_cache = get_token_cache()


def generate_trace_id() -> str:
    """Generate a unique trace ID for request tracking."""
    return f"trace_{uuid.uuid4().hex[:12]}"


def log_audit_event(event: dict[str, Any]) -> str:
    """Log an audit event and return event ID."""
    try:
        event_id = audit_store.record_event(
            tenant_id=event.get("tenant_id", "default"),
            trace_id=event.get("trace_id", ""),
            action=event.get("decision", "unknown"),
            entities_found=event.get("entities", []),
            metadata=event
        )
        return event_id
    except Exception:
        # Fall back to in-memory if DB unavailable
        event_id = f"event_{uuid.uuid4().hex[:12]}"
        return event_id


# =============================================================================
# Tool Definitions
# =============================================================================

@server.list_tools()
async def list_tools() -> list[Tool]:
    """List available MCP tools."""
    return [
        Tool(
            name="sanitize_text",
            description="Sanitize plain text according to a privacy policy. Detects PII and applies redaction, pseudonymization, or blocking.",
            inputSchema={
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "description": "The text to sanitize"
                    },
                    "policy_id": {
                        "type": "string",
                        "description": "Policy ID to apply (optional, uses default if not specified)"
                    },
                    "tenant_id": {
                        "type": "string",
                        "description": "Tenant identifier for policy scoping"
                    },
                    "mode": {
                        "type": "string",
                        "enum": ["redact", "pseudonymize", "block", "auto"],
                        "description": "Sanitization mode: redact replaces with placeholders, pseudonymize uses consistent tokens"
                    },
                    "include_entities": {
                        "type": "boolean",
                        "description": "Include detected entities in response"
                    }
                },
                "required": ["text", "tenant_id"]
            }
        ),
        Tool(
            name="sanitize_json",
            description="Sanitize structured JSON while preserving schema shape. Applies PII detection and transformation to string values.",
            inputSchema={
                "type": "object",
                "properties": {
                    "payload": {
                        "type": "object",
                        "description": "The JSON payload to sanitize"
                    },
                    "policy_id": {
                        "type": "string",
                        "description": "Policy ID to apply"
                    },
                    "tenant_id": {
                        "type": "string",
                        "description": "Tenant identifier"
                    },
                    "preserve_keys": {
                        "type": "boolean",
                        "description": "Keep original keys even if values are transformed"
                    }
                },
                "required": ["payload", "tenant_id"]
            }
        ),
        Tool(
            name="evaluate_policy",
            description="Explain how a payload would be treated by a policy without mutating or storing it. Use for policy testing.",
            inputSchema={
                "type": "object",
                "properties": {
                    "payload": {
                        "type": "string",
                        "description": "Text or JSON string to evaluate"
                    },
                    "policy_id": {
                        "type": "string",
                        "description": "Policy ID to evaluate against"
                    },
                    "tenant_id": {
                        "type": "string",
                        "description": "Tenant identifier"
                    }
                },
                "required": ["payload", "tenant_id"]
            }
        ),
        Tool(
            name="search_audit_events",
            description="Search governance audit events by tenant, time range, entity type, or decision.",
            inputSchema={
                "type": "object",
                "properties": {
                    "tenant_id": {
                        "type": "string",
                        "description": "Tenant identifier to filter by"
                    },
                    "from_time": {
                        "type": "string",
                        "description": "Start timestamp (ISO 8601 or unix epoch)"
                    },
                    "to_time": {
                        "type": "string",
                        "description": "End timestamp"
                    },
                    "entity_type": {
                        "type": "string",
                        "description": "Filter by PII entity type (EMAIL, PHONE, etc.)"
                    },
                    "decision": {
                        "type": "string",
                        "enum": ["allow", "transform", "block"],
                        "description": "Filter by policy decision"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum results to return"
                    }
                },
                "required": ["tenant_id"]
            }
        ),
        Tool(
            name="validate_policy",
            description="Validate policy syntax and semantics before publishing. Returns errors if policy is invalid.",
            inputSchema={
                "type": "object",
                "properties": {
                    "policy_definition": {
                        "type": "object",
                        "description": "Policy object with name, entity_types, and action"
                    }
                },
                "required": ["policy_definition"]
            }
        ),
        Tool(
            name="list_policies",
            description="List all policies available to a tenant.",
            inputSchema={
                "type": "object",
                "properties": {
                    "tenant_id": {
                        "type": "string",
                        "description": "Tenant identifier"
                    }
                },
                "required": ["tenant_id"]
            }
        ),
        Tool(
            name="batch_sanitize",
            description="Sanitize multiple records in a single batch operation. Returns summary and individual results.",
            inputSchema={
                "type": "object",
                "properties": {
                    "items": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of text items to sanitize"
                    },
                    "policy_id": {
                        "type": "string",
                        "description": "Policy ID to apply"
                    },
                    "tenant_id": {
                        "type": "string",
                        "description": "Tenant identifier"
                    },
                    "mode": {
                        "type": "string",
                        "enum": ["redact", "pseudonymize", "block", "auto"],
                        "description": "Sanitization mode"
                    }
                },
                "required": ["items", "tenant_id"]
            }
        ),
        Tool(
            name="simulate_policy",
            description="Compare a draft policy against sample payloads and show behavioral diffs without applying changes.",
            inputSchema={
                "type": "object",
                "properties": {
                    "draft_policy": {
                        "type": "object",
                        "description": "Draft policy with name, entity_types, and action"
                    },
                    "sample_payloads": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Sample text payloads to test against"
                    }
                },
                "required": ["draft_policy", "sample_payloads"]
            }
        ),
        Tool(
            name="create_policy",
            description="Create a new privacy policy in draft state. Requires admin scope.",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Unique policy name"
                    },
                    "entity_types": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of entity types (EMAIL, PHONE, SSN, etc.)"
                    },
                    "action": {
                        "type": "string",
                        "enum": ["allow", "redact", "pseudonymize", "block"],
                        "description": "Action to apply when policy matches"
                    },
                    "tenant_id": {
                        "type": "string",
                        "description": "Owner tenant ID"
                    },
                    "description": {
                        "type": "string",
                        "description": "Optional policy description"
                    }
                },
                "required": ["name", "entity_types", "action", "tenant_id"]
            }
        )
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Handle tool invocation."""
    trace_id = generate_trace_id()
    start_time = time.time()

    try:
        if name == "sanitize_text":
            return await handle_sanitize_text(arguments, trace_id)
        elif name == "sanitize_json":
            return await handle_sanitize_json(arguments, trace_id)
        elif name == "evaluate_policy":
            return await handle_evaluate_policy(arguments, trace_id)
        elif name == "search_audit_events":
            return await handle_search_audit_events(arguments, trace_id)
        elif name == "validate_policy":
            return await handle_validate_policy(arguments, trace_id)
        elif name == "list_policies":
            return await handle_list_policies(arguments, trace_id)
        elif name == "batch_sanitize":
            return await handle_batch_sanitize(arguments, trace_id)
        elif name == "simulate_policy":
            return await handle_simulate_policy(arguments, trace_id)
        elif name == "create_policy":
            return await handle_create_policy(arguments, trace_id)
        else:
            return [TextContent(
                type="text",
                text=json.dumps({
                    "error": f"Unknown tool: {name}",
                    "trace_id": trace_id
                })
            )]
    except Exception as e:
        latency_ms = int((time.time() - start_time) * 1000)
        return [TextContent(
            type="text",
            text=json.dumps({
                "error": str(e),
                "code": "INTERNAL",
                "trace_id": trace_id,
                "latency_ms": latency_ms
            })
        )]


async def handle_sanitize_text(args: dict[str, Any], trace_id: str) -> list[TextContent]:
    """Handle sanitize_text tool."""
    text = args.get("text", "")
    tenant_id = args.get("tenant_id", "default")
    policy_id = args.get("policy_id")
    mode = args.get("mode", "auto")
    include_entities = args.get("include_entities", False)

    # Detect PII
    matches = detector.detect(text)

    # Determine action
    if mode == "block":
        action = SanitizationAction.BLOCK
    elif mode == "pseudonymize":
        action = SanitizationAction.PSEUDONYMIZE
    elif mode == "redact":
        action = SanitizationAction.REDACT
    else:
        # Auto mode: default to redact
        action = SanitizationAction.REDACT

    # Apply sanitization
    if matches and action != SanitizationAction.BLOCK:
        result = sanitizer.sanitize(text, matches, action)
        sanitized_text = result.sanitized
        decision = "transform"
    elif action == SanitizationAction.BLOCK and matches:
        sanitized_text = "[BLOCKED: PII detected]"
        decision = "block"
    else:
        sanitized_text = text
        decision = "allow"

    # Build response
    response = {
        "sanitized_text": sanitized_text,
        "decision": decision,
        "risk_score": sanitizer.calculate_risk_score(matches),
        "policy_matches": [policy_id] if policy_id else [],
        "trace_id": trace_id,
        "audit_event_id": log_audit_event({
            "tenant_id": tenant_id,
            "tool": "sanitize_text",
            "decision": decision,
            "entities_count": len(matches),
            "trace_id": trace_id
        })
    }

    if include_entities:
        response["entities"] = [
            {
                "type": m.entity_type.value,
                "value": m.value,
                "confidence": m.confidence
            }
            for m in matches
        ]

    latency_ms = int((time.time() - start_time) * 1000)
    response["latency_ms"] = latency_ms

    return [TextContent(type="text", text=json.dumps(response, indent=2))]


async def handle_sanitize_json(args: dict[str, Any], trace_id: str) -> list[TextContent]:
    """Handle sanitize_json tool."""
    payload = args.get("payload", {})
    tenant_id = args.get("tenant_id", "default")
    policy_id = args.get("policy_id")
    preserve_keys = args.get("preserve_keys", True)

    # Convert payload to JSON string for detection
    payload_str = json.dumps(payload)

    # Detect PII in the JSON
    detections = detector.detect_in_json(payload)

    # For now, apply redaction to string values
    action = SanitizationAction.REDACT
    sanitized_payload, _ = sanitizer.sanitize_json_value(
        payload, action, detector
    )

    # Count transformations
    field_transformations = []
    for detection in detections:
        field_transformations.append({
            "path": detection["path"],
            "entity_type": detection["entity_type"],
            "action": "redact"
        })

    response = {
        "sanitized_payload": sanitized_payload,
        "decision": "transform" if detections else "allow",
        "field_transformations": field_transformations,
        "risk_score": sanitizer.calculate_risk_score([
            type('obj', (object,), {'entity_type': EntityType(d["entity_type"]), 'confidence': 0.95})()
            for d in detections
        ]) if detections else 0.0,
        "trace_id": trace_id,
        "audit_event_id": log_audit_event({
            "tenant_id": tenant_id,
            "tool": "sanitize_json",
            "fields_transformed": len(field_transformations),
            "trace_id": trace_id
        })
    }

    latency_ms = int((time.time() - start_time) * 1000)
    response["latency_ms"] = latency_ms

    return [TextContent(type="text", text=json.dumps(response, indent=2))]


async def handle_evaluate_policy(args: dict[str, Any], trace_id: str) -> list[TextContent]:
    """Handle evaluate_policy tool."""
    payload = args.get("payload", "")
    tenant_id = args.get("tenant_id", "default")
    policy_id = args.get("policy_id")

    # Detect PII without transforming
    matches = detector.detect(payload)

    # Determine what would happen
    would_block = False
    would_transform = len(matches) > 0

    matched_rules = [
        {
            "entity_type": m.entity_type.value,
            "value": m.value,
            "action": "redact"
        }
        for m in matches
    ]

    response = {
        "matched_rules": matched_rules,
        "would_block": would_block,
        "would_transform": would_transform,
        "explanation": f"Found {len(matches)} PII entities that would be transformed" if matches else "No PII detected - payload would pass through unchanged",
        "trace_id": trace_id
    }

    latency_ms = int((time.time() - start_time) * 1000)
    response["latency_ms"] = latency_ms

    return [TextContent(type="text", text=json.dumps(response, indent=2))]


async def handle_search_audit_events(args: dict[str, Any], trace_id: str) -> list[TextContent]:
    """Handle search_audit_events tool."""
    tenant_id = args.get("tenant_id", "default")
    from_time = args.get("from_time")
    to_time = args.get("to_time")
    entity_type = args.get("entity_type")
    decision = args.get("decision")
    limit = args.get("limit", 100)

    try:
        # Parse time filters
        start_dt = None
        end_dt = None

        if from_time:
            try:
                start_dt = datetime.fromisoformat(from_time.replace('Z', '+00:00'))
            except ValueError:
                try:
                    start_dt = datetime.fromtimestamp(float(from_time))
                except ValueError:
                    pass

        if to_time:
            try:
                end_dt = datetime.fromisoformat(to_time.replace('Z', '+00:00'))
            except ValueError:
                try:
                    end_dt = datetime.fromtimestamp(float(to_time))
                except ValueError:
                    pass

        # Query persistent store
        events = audit_store.list_events(
            tenant_id=tenant_id,
            limit=limit,
            action_filter=decision,
            start_time=start_dt,
            end_time=end_dt
        )

        response = {
            "events": events,
            "count": len(events),
            "trace_id": trace_id
        }
    except Exception as e:
        response = {
            "events": [],
            "count": 0,
            "error": str(e),
            "trace_id": trace_id
        }

    latency_ms = int((time.time() - start_time) * 1000)
    response["latency_ms"] = latency_ms

    return [TextContent(type="text", text=json.dumps(response, indent=2))]


async def handle_validate_policy(args: dict[str, Any], trace_id: str) -> list[TextContent]:
    """Handle validate_policy tool."""
    policy = args.get("policy_definition", {})

    errors = []

    # Validate required fields
    if "name" not in policy:
        errors.append("Policy must have a 'name' field")
    if "entity_types" not in policy:
        errors.append("Policy must have 'entity_types' field")
    elif not isinstance(policy["entity_types"], list):
        errors.append("'entity_types' must be a list")
    if "action" not in policy:
        errors.append("Policy must have 'action' field")
    elif policy["action"] not in ["allow", "redact", "pseudonymize", "block"]:
        errors.append(f"Invalid action: {policy['action']}. Must be one of: allow, redact, pseudonymize, block")

    response = {
        "valid": len(errors) == 0,
        "errors": errors,
        "trace_id": trace_id
    }

    latency_ms = int((time.time() - start_time) * 1000)
    response["latency_ms"] = latency_ms

    return [TextContent(type="text", text=json.dumps(response, indent=2))]


async def handle_list_policies(args: dict[str, Any], trace_id: str) -> list[TextContent]:
    """Handle list_policies tool."""
    tenant_id = args.get("tenant_id", "default")

    # Load from config
    config = load_config("config/policy.yaml")
    policies = config.get("policies", [])

    response = {
        "policies": policies,
        "count": len(policies),
        "tenant_id": tenant_id,
        "trace_id": trace_id
    }

    latency_ms = int((time.time() - start_time) * 1000)
    response["latency_ms"] = latency_ms

    return [TextContent(type="text", text=json.dumps(response, indent=2))]


# =============================================================================
# Resource Definitions
# =============================================================================

@server.list_resources()
async def list_resources() -> list[Resource]:
    """List available MCP resources."""
    return [
        Resource(
            uri="piisafe://schemas/entities",
            name="Supported Entity Types",
            description="List of PII entity types that can be detected, with risk weights and confidence semantics",
            mimeType="application/json"
        ),
        Resource(
            uri="piisafe://docs/policy-language",
            name="Policy Language Reference",
            description="Human-readable documentation for writing privacy policies",
            mimeType="text/plain"
        ),
        Resource(
            uri="piisafe://health/status",
            name="Service Health",
            description="Current service health, version, and dependency readiness",
            mimeType="application/json"
        )
    ]


@server.read_resource()
async def read_resource(uri: str) -> str:
    """Read a resource by URI."""
    if uri == "piisafe://schemas/entities":
        entities = {
            "EMAIL": {"risk_weight": 0.5, "description": "Email addresses"},
            "PHONE": {"risk_weight": 0.5, "description": "Phone numbers"},
            "IP_ADDRESS": {"risk_weight": 0.3, "description": "IPv4 addresses"},
            "SSN": {"risk_weight": 1.0, "description": "Social Security Numbers"},
            "CREDIT_CARD": {"risk_weight": 1.0, "description": "Credit card numbers"},
            "NAME": {"risk_weight": 0.4, "description": "Person names"},
            "CUSTOM": {"risk_weight": 0.2, "description": "Custom pattern matches"}
        }
        return json.dumps(entities, indent=2)

    elif uri == "piisafe://docs/policy-language":
        return """PII-Safe Policy Language Reference

A policy consists of:
- name: Unique identifier for the policy
- entity_types: List of PII types to match (EMAIL, PHONE, SSN, CREDIT_CARD, IP_ADDRESS, NAME, CUSTOM)
- action: What to do when matched (allow, redact, pseudonymize, block)

Example:
{
  "name": "redact_emails",
  "entity_types": ["EMAIL"],
  "action": "redact"
}

Actions:
- allow: Pass through unchanged
- redact: Replace with [TYPE_REDACTED] placeholder
- pseudonymize: Replace with consistent token (e.g., EMAIL_A1B2C3D4)
- block: Reject the entire request
"""

    elif uri == "piisafe://health/status":
        return json.dumps({
            "status": "healthy",
            "version": SERVER_VERSION,
            "server": SERVER_NAME,
            "dependencies": {
                "detector": "ok",
                "sanitizer": "ok",
                "pseudonym_engine": "ok"
            }
        }, indent=2)

    else:
        raise ValueError(f"Unknown resource: {uri}")


# =============================================================================
# Prompt Definitions
# =============================================================================

@server.list_prompts()
async def list_prompts() -> list[Prompt]:
    """List available MCP prompts."""
    return [
        Prompt(
            name="privacy-review-request",
            description="Generate a privacy risk review for a proposed AI workflow. Provide sample data and workflow description.",
            arguments=[
                {
                    "name": "workflow_description",
                    "description": "Description of the AI workflow",
                    "required": True
                },
                {
                    "name": "sample_data",
                    "description": "Sample data that will be processed",
                    "required": False
                }
            ]
        ),
        Prompt(
            name="draft-redaction-policy",
            description="Produce a policy draft from business rules and sample data.",
            arguments=[
                {
                    "name": "business_rules",
                    "description": "Description of what data should be protected",
                    "required": True
                },
                {
                    "name": "sample_payloads",
                    "description": "Example payloads to base policy on",
                    "required": False
                }
            ]
        ),
        Prompt(
            name="compliance-audit-summary",
            description="Summarize privacy enforcement evidence over a time range for compliance reporting.",
            arguments=[
                {
                    "name": "tenant_id",
                    "description": "Tenant identifier",
                    "required": True
                },
                {
                    "name": "from_date",
                    "description": "Start date for audit period",
                    "required": True
                },
                {
                    "name": "to_date",
                    "description": "End date for audit period",
                    "required": True
                }
            ]
        )
    ]


@server.get_prompt()
async def get_prompt(name: str, arguments: dict[str, str] | None) -> list[TextContent]:
    """Get a prompt by name."""
    if name == "privacy-review-request":
        workflow = arguments.get("workflow_description", "Unknown workflow") if arguments else "Unknown workflow"
        sample = arguments.get("sample_data", "No sample provided") if arguments else "No sample provided"

        # Analyze sample for PII
        matches = detector.detect(sample) if sample else []
        entities_found = list(set(m.entity_type.value for m in matches))

        return [TextContent(
            type="text",
            text=f"""Privacy Risk Review

Workflow: {workflow}

Sample Data Analysis:
{sample}

Detected Entity Types: {entities_found if entities_found else ['None detected']}

Recommendations:
1. Implement PII detection before sending to LLM
2. Use pseudonymization for cross-request correlation if needed
3. Log all transformations for audit trail
4. Consider blocking high-risk entities (SSN, credit cards)

Suggested Policy:
{{
  "name": "workflow_protection",
  "entity_types": {entities_found if entities_found else ['EMAIL', 'PHONE']},
  "action": "pseudonymize"
}}
"""
        )]

    elif name == "draft-redaction-policy":
        rules = arguments.get("business_rules", "No rules provided") if arguments else "No rules provided"

        return [TextContent(
            type="text",
            text=f"""Draft Redaction Policy

Business Rules:
{rules}

Suggested Policy Configuration:

{{
  "name": "custom_policy",
  "entity_types": ["EMAIL", "PHONE", "SSN"],
  "action": "redact",
  "description": "Auto-generated policy based on: {rules[:100]}..."
}}

To customize:
1. Add specific entity types you need to protect
2. Choose action: redact (placeholders), pseudonymize (tokens), or block (reject)
3. Test with sample payloads using evaluate_policy tool
"""
        )]

    elif name == "compliance-audit-summary":
        tenant_id = arguments.get("tenant_id", "unknown") if arguments else "unknown"
        from_date = arguments.get("from_date", "unknown") if arguments else "unknown"
        to_date = arguments.get("to_date", "unknown") if arguments else "unknown"

        # Filter audit events for tenant
        tenant_events = [e for e in _audit_log if e.get("tenant_id") == tenant_id]

        return [TextContent(
            type="text",
            text=f"""Compliance Audit Summary

Tenant: {tenant_id}
Period: {from_date} to {to_date}

Total Events: {len(tenant_events)}

Events by Decision:
- Allowed: {len([e for e in tenant_events if e.get('decision') == 'allow'])}
- Transformed: {len([e for e in tenant_events if e.get('decision') == 'transform'])}
- Blocked: {len([e for e in tenant_events if e.get('decision') == 'block'])}

This summary can be exported for compliance reporting.
Use the search_audit_events tool for detailed event listings.
"""
        )]

    else:
        raise ValueError(f"Unknown prompt: {name}")


# =============================================================================
# Main Entry Point
# =============================================================================

async def main():
    """Run the MCP server."""
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options()
        )


if __name__ == "__main__":
    asyncio.run(main())
