from __future__ import annotations

import json
import re
from typing import Any

ALLOWED_OPERATIONS = frozenset(
    {
        "list_entities",
        "get_state",
        "get_history",
        "get_logbook",
        "get_automation_config",
        "get_automation_traces",
        "get_system_health",
    }
)
MAX_RESULT_BYTES = 262_144
MAX_ENTITIES = 100
MAX_HISTORY_ENTITIES = 20
MAX_LOOKBACK_HOURS = 72
MAX_TRACES = 20
MAX_LOG_ENTRIES = 50

_ENTITY_ID = re.compile(r"^[a-z0-9_]+\.[a-z0-9_]+$")
_DOMAIN = re.compile(r"^[a-z0-9_]+$")
_AUTOMATION_ID = re.compile(r"^[A-Za-z0-9_-]+$")


class OperationError(ValueError):
    pass


def normalize_automation_id(value: Any) -> str:
    if not isinstance(value, str):
        raise OperationError("automation_id must be a string")
    normalized = value.removeprefix("automation.")
    if not normalized or len(normalized) > 128 or not _AUTOMATION_ID.fullmatch(normalized):
        raise OperationError("automation_id has an invalid format")
    return normalized


def validate_operation(operation: Any, params: Any) -> tuple[str, dict[str, Any]]:
    if not isinstance(operation, str) or operation not in ALLOWED_OPERATIONS:
        raise OperationError("operation is not in the read-only allowlist")
    if not isinstance(params, dict):
        raise OperationError("params must be an object")

    allowed = {
        "list_entities": {"domain", "max_results"},
        "get_state": {"entity_id"},
        "get_history": {"entity_ids", "hours", "max_results"},
        "get_logbook": {"entity_id", "hours", "max_results"},
        "get_automation_config": {"automation_id"},
        "get_automation_traces": {"automation_id", "max_results"},
        "get_system_health": {"max_log_entries"},
    }[operation]
    unknown = set(params) - allowed
    if unknown:
        raise OperationError(f"unsupported parameter for {operation}: {sorted(unknown)[0]}")

    clean: dict[str, Any] = {}
    if operation == "list_entities":
        domain = params.get("domain")
        if domain is not None:
            if not isinstance(domain, str) or len(domain) > 64 or not _DOMAIN.fullmatch(domain):
                raise OperationError("domain has an invalid format")
            clean["domain"] = domain
        clean["max_results"] = _bounded_int(params.get("max_results", 100), "max_results", 1, MAX_ENTITIES)
    elif operation == "get_state":
        clean["entity_id"] = _entity_id(params.get("entity_id"))
    elif operation == "get_history":
        entity_ids = params.get("entity_ids")
        if isinstance(entity_ids, str):
            entity_ids = [entity_ids]
        if not isinstance(entity_ids, list) or not 1 <= len(entity_ids) <= MAX_HISTORY_ENTITIES:
            raise OperationError(f"entity_ids must contain 1 to {MAX_HISTORY_ENTITIES} entity IDs")
        clean["entity_ids"] = [_entity_id(value) for value in entity_ids]
        if len(set(clean["entity_ids"])) != len(clean["entity_ids"]):
            raise OperationError("entity_ids must not contain duplicates")
        clean["hours"] = _bounded_int(params.get("hours", 24), "hours", 1, MAX_LOOKBACK_HOURS)
        clean["max_results"] = _bounded_int(params.get("max_results", 100), "max_results", 1, MAX_ENTITIES)
    elif operation == "get_logbook":
        if params.get("entity_id") is not None:
            clean["entity_id"] = _entity_id(params["entity_id"])
        clean["hours"] = _bounded_int(params.get("hours", 24), "hours", 1, MAX_LOOKBACK_HOURS)
        clean["max_results"] = _bounded_int(params.get("max_results", 100), "max_results", 1, MAX_ENTITIES)
    elif operation in {"get_automation_config", "get_automation_traces"}:
        clean["automation_id"] = normalize_automation_id(params.get("automation_id"))
        if operation == "get_automation_traces":
            clean["max_results"] = _bounded_int(params.get("max_results", 10), "max_results", 1, MAX_TRACES)
    elif operation == "get_system_health":
        clean["max_log_entries"] = _bounded_int(
            params.get("max_log_entries", 20), "max_log_entries", 1, MAX_LOG_ENTRIES
        )
    return operation, clean


def ensure_result_size(value: Any) -> None:
    try:
        size = len(json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8"))
    except (TypeError, ValueError) as exc:
        raise OperationError("operation returned data that is not JSON serializable") from exc
    if size > MAX_RESULT_BYTES:
        raise OperationError(f"operation result exceeds the {MAX_RESULT_BYTES}-byte limit")


def _entity_id(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 255 or not _ENTITY_ID.fullmatch(value):
        raise OperationError("entity_id has an invalid format")
    return value


def _bounded_int(value: Any, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise OperationError(f"{name} must be an integer from {minimum} to {maximum}")
    return value
