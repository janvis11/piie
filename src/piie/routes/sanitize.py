"""
Sanitize API Routes

Endpoints for sanitizing text and JSON payloads.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, Optional, List, Union

from ..detectors import PIIDetector
from ..sanitizers import PIISanitizer, SanitizationAction, PseudonymizationEngine
from ..config import get_pseudonymization_config

router = APIRouter(prefix="/sanitize", tags=["sanitization"])


class SanitizeRequest(BaseModel):
    """Request body for sanitization endpoint."""
    content: Union[str, Dict[str, Any]]
    action: Optional[str] = "redact"
    entity_types: Optional[List[str]] = None


class SanitizeResponse(BaseModel):
    """Response body for sanitization endpoint."""
    original: Union[str, Dict[str, Any]]
    sanitized: Union[str, Dict[str, Any]]
    entities_found: int
    transformations: List[Dict[str, Any]]
    risk_score: float


@router.post("", response_model=SanitizeResponse)
@router.post("/", response_model=SanitizeResponse)
async def sanitize(request: SanitizeRequest):
    """
    Sanitize a single text or JSON payload.

    Detects PII in the input and applies the specified action.

    Args:
        request: SanitizeRequest with content and optional action/entity_types

    Returns:
        SanitizeResponse with original, sanitized content, and metadata
    """
    detector = PIIDetector()
    pseudo_config = get_pseudonymization_config()
    sanitizer = PIISanitizer(PseudonymizationEngine(salt=pseudo_config.salt))

    try:
        action = SanitizationAction(request.action or "redact")
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid action: {request.action}. Must be one of: allow, redact, pseudonymize, block"
        )

    # Handle string vs JSON differently
    if isinstance(request.content, str):
        # String sanitization (original behavior)
        matches = detector.detect(request.content)

        # Filter by entity types if specified
        if request.entity_types:
            matches = [m for m in matches if m.entity_type.value in request.entity_types]

        result = sanitizer.sanitize(request.content, matches, action)
        sanitized_content = result.sanitized
        all_matches = matches
    else:
        # JSON sanitization with structure preservation
        sanitized_content, all_matches = sanitizer.sanitize_json_value(
            request.content, action, detector
        )

        # Filter by entity types if specified
        if request.entity_types:
            all_matches = [m for m in all_matches if m.entity_type.value in request.entity_types]

    # Build transformations list - SECURITY: never return original PII
    transformations = []
    for match in all_matches:
        # Use hash for debugging without exposing PII
        import hashlib
        value_hash = hashlib.sha256(match.value.encode()).hexdigest()[:8]
        transformations.append({
            "entity_type": match.entity_type.value,
            "value_hash": f"{match.entity_type.value}_{value_hash}",
            "confidence": match.confidence,
            "position": f"{match.start_pos}-{match.end_pos}"
        })

    return SanitizeResponse(
        original="[REDACTED]" if all_matches else request.content,
        sanitized=sanitized_content,
        entities_found=len(all_matches),
        transformations=transformations,
        risk_score=sanitizer.calculate_risk_score(all_matches)
    )


@router.post("/text", response_model=SanitizeResponse)
async def sanitize_text(text: str, action: Optional[str] = "redact"):
    """
    Sanitize plain text.

    Args:
        text: Text to sanitize
        action: Action to apply (redact, pseudonymize, allow)

    Returns:
        Sanitized text with metadata
    """
    return await sanitize(SanitizeRequest(content=text, action=action))


@router.post("/json", response_model=SanitizeResponse)
async def sanitize_json(data: Dict[str, Any], action: Optional[str] = "redact"):
    """
    Sanitize JSON object.

    Args:
        data: JSON object to sanitize
        action: Action to apply

    Returns:
        Sanitized JSON with metadata
    """
    return await sanitize(SanitizeRequest(content=data, action=action))
