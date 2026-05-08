"""
Policy API Routes

Endpoints for managing privacy policies.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import yaml
import os

from .. import config as config_module

router = APIRouter(prefix="/policy", tags=["policy"])
POLICY_CONFIG_PATH = "config/policy.yaml"
_TEST_CONFIG_CACHE: Optional[Dict[str, Any]] = None
_TEST_CONFIG_LOADER_ID: Optional[int] = None


def _load_policy_config() -> Dict[str, Any]:
    """Load policy config, using an in-memory copy during tests."""
    global _TEST_CONFIG_CACHE, _TEST_CONFIG_LOADER_ID

    if os.environ.get("PIIE_TEST_MODE") == "true":
        loader_id = id(config_module.load_config)
        if _TEST_CONFIG_CACHE is None or _TEST_CONFIG_LOADER_ID != loader_id:
            _TEST_CONFIG_CACHE = config_module.load_config(POLICY_CONFIG_PATH)
            _TEST_CONFIG_LOADER_ID = loader_id
        return _TEST_CONFIG_CACHE

    return config_module.load_config(POLICY_CONFIG_PATH)


def _save_policy_config(config: Dict[str, Any]) -> None:
    """Save policy config, avoiding real file writes during tests."""
    global _TEST_CONFIG_CACHE

    if os.environ.get("PIIE_TEST_MODE") == "true":
        _TEST_CONFIG_CACHE = config
        return

    with open(POLICY_CONFIG_PATH, "w") as f:
        yaml.dump(config, f, default_flow_style=False)


class PolicyInput(BaseModel):
    """Input for creating/updating a policy."""
    name: str
    entity_types: List[str]
    action: str


class PolicyResponse(BaseModel):
    """Policy response."""
    name: str
    entity_types: List[str]
    action: str


class ConfigResponse(BaseModel):
    """Full configuration response."""
    policies: List[PolicyResponse]
    audit_logging: bool
    risk_scoring: bool


@router.get("", response_model=ConfigResponse)
@router.get("/", response_model=ConfigResponse)
async def get_policy():
    """
    Get current privacy policy configuration.

    Returns:
        Current configuration with all policies
    """
    config = _load_policy_config()
    return ConfigResponse(
        policies=[
            PolicyResponse(
                name=p["name"],
                entity_types=p["entity_types"],
                action=p["action"]
            )
            for p in config.get("policies", [])
        ],
        audit_logging=config.get("audit_logging", True),
        risk_scoring=config.get("risk_scoring", True)
    )


@router.post("", response_model=ConfigResponse)
@router.post("/", response_model=ConfigResponse)
async def update_policy(config: ConfigResponse):
    """
    Update privacy policy configuration.

    Args:
        config: New configuration

    Returns:
        Updated configuration
    """
    config_dict = {
        "policies": [
            {
                "name": p.name,
                "entity_types": p.entity_types,
                "action": p.action
            }
            for p in config.policies
        ],
        "audit_logging": config.audit_logging,
        "risk_scoring": config.risk_scoring
    }

    try:
        config_module.validate_config(config_dict)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    _save_policy_config(config_dict)

    return config


@router.post("/add", response_model=ConfigResponse)
async def add_policy(policy: PolicyInput):
    """
    Add a new policy to the configuration.

    Args:
        policy: Policy to add

    Returns:
        Updated configuration
    """
    config = _load_policy_config()

    # Check for duplicate name
    for existing in config.get("policies", []):
        if existing["name"] == policy.name:
            raise HTTPException(
                status_code=400,
                detail=f"Policy with name '{policy.name}' already exists"
            )

    # Validate action
    valid_actions = {"allow", "redact", "pseudonymize", "block"}
    if policy.action.lower() not in valid_actions:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid action: {policy.action}. Must be one of: {valid_actions}"
        )

    config["policies"].append({
        "name": policy.name,
        "entity_types": policy.entity_types,
        "action": policy.action.lower()
    })

    _save_policy_config(config)

    return ConfigResponse(
        policies=[
            PolicyResponse(
                name=p["name"],
                entity_types=p["entity_types"],
                action=p["action"]
            )
            for p in config.get("policies", [])
        ],
        audit_logging=config.get("audit_logging", True),
        risk_scoring=config.get("risk_scoring", True)
    )


@router.delete("/{policy_name}", response_model=ConfigResponse)
async def delete_policy(policy_name: str):
    """
    Delete a policy by name.

    Args:
        policy_name: Name of policy to delete

    Returns:
        Updated configuration
    """
    config = _load_policy_config()

    original_count = len(config.get("policies", []))
    config["policies"] = [
        p for p in config.get("policies", [])
        if p["name"] != policy_name
    ]

    if len(config["policies"]) == original_count:
        raise HTTPException(
            status_code=404,
            detail=f"Policy '{policy_name}' not found"
        )

    _save_policy_config(config)

    return ConfigResponse(
        policies=[
            PolicyResponse(
                name=p["name"],
                entity_types=p["entity_types"],
                action=p["action"]
            )
            for p in config.get("policies", [])
        ],
        audit_logging=config.get("audit_logging", True),
        risk_scoring=config.get("risk_scoring", True)
    )


@router.get("/reset", response_model=ConfigResponse)
async def reset_policy():
    """
    Reset to default configuration.

    Returns:
        Default configuration
    """
    config = config_module.create_default_config()

    _save_policy_config(config)

    return ConfigResponse(
        policies=[
            PolicyResponse(
                name=p["name"],
                entity_types=p["entity_types"],
                action=p["action"]
            )
            for p in config.get("policies", [])
        ],
        audit_logging=config.get("audit_logging", True),
        risk_scoring=config.get("risk_scoring", True)
    )
