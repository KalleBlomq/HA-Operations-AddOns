from __future__ import annotations

import json
import re
from pathlib import Path
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
        "list_config_files",
        "get_config_file",
        "list_dashboards",
        "get_dashboard",
    }
)
MAX_RESULT_BYTES = 262_144
MAX_ENTITIES = 100
MAX_HISTORY_ENTITIES = 20
MAX_LOOKBACK_HOURS = 72
MAX_TRACES = 20
MAX_LOG_ENTRIES = 50
MAX_CONFIG_FILE_BYTES = 131_072

_ENTITY_ID = re.compile(r"^[a-z0-9_]+\.[a-z0-9_]+$")
_DOMAIN = re.compile(r"^[a-z0-9_]+$")
_AUTOMATION_ID = re.compile(r"^[A-Za-z0-9_-]+$")
_CONFIG_PATH = re.compile(
    r"^(?:(?:configuration|automations|scripts|scenes)\.yaml|"
    r"(?:packages|dashboards)/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\.ya?ml)$"
)
_DASHBOARD_ID = re.compile(r"^(?:yaml|storage):[A-Za-z0-9_.-]+$")
_SENSITIVE_KEY = re.compile(
    r"(?:password|passwd|token|secret|api[_-]?key|client[_-]?secret|"
    r"access[_-]?token|authorization|credential)",
    re.IGNORECASE,
)
_ABSOLUTE_URL = re.compile(r"https?://[^\s'\"<>{}\[\]]+", re.IGNORECASE)
_SENSITIVE_YAML_LINE = re.compile(
    r"^(\s*[^#\n:]*"
    r"(?:password|passwd|token|secret|api[_-]?key|client[_-]?secret|"
    r"access[_-]?token|authorization|credential)"
    r"[^:\n]*:\s*)(.*)$",
    re.IGNORECASE,
)


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
        "list_entities": {"domain", "query", "max_results"},
        "get_state": {"entity_id"},
        "get_history": {"entity_ids", "hours", "max_results"},
        "get_logbook": {"entity_id", "hours", "max_results"},
        "get_automation_config": {"automation_id"},
        "get_automation_traces": {"automation_id", "max_results"},
        "get_system_health": {"max_log_entries"},
        "list_config_files": set(),
        "get_config_file": {"path"},
        "list_dashboards": set(),
        "get_dashboard": {"dashboard_id"},
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
        query = params.get("query")
        if query is not None:
            if not isinstance(query, str):
                raise OperationError("query must be a string")
            query = query.strip()
            if not query or len(query) > 100 or any(ord(character) < 32 for character in query):
                raise OperationError("query has an invalid format")
            clean["query"] = query
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
    elif operation == "get_config_file":
        clean["path"] = normalize_config_path(params.get("path"))
    elif operation == "get_dashboard":
        clean["dashboard_id"] = _pattern(
            params.get("dashboard_id"), "dashboard_id", _DASHBOARD_ID, 160
        )
    return operation, clean


def ensure_result_size(value: Any) -> None:
    try:
        size = len(json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8"))
    except (TypeError, ValueError) as exc:
        raise OperationError("operation returned data that is not JSON serializable") from exc
    if size > MAX_RESULT_BYTES:
        raise OperationError(f"operation result exceeds the {MAX_RESULT_BYTES}-byte limit")


def matches_entity_query(state: dict[str, Any], query: str) -> bool:
    attributes = state.get("attributes")
    friendly_name = attributes.get("friendly_name", "") if isinstance(attributes, dict) else ""
    haystack = f"{state.get('entity_id', '')} {friendly_name}".casefold()
    return all(term in haystack for term in query.casefold().split())


def normalize_config_path(value: Any) -> str:
    if not isinstance(value, str):
        raise OperationError("path must be a string")
    normalized = value.strip().replace("\\", "/")
    if (
        not normalized
        or len(normalized) > 255
        or normalized.startswith("/")
        or ".." in normalized.split("/")
        or not _CONFIG_PATH.fullmatch(normalized)
    ):
        raise OperationError("path is not in the read-only config allowlist")
    return normalized


def resolve_config_path(root: Path, relative_path: str) -> Path:
    normalized = normalize_config_path(relative_path)
    resolved_root = root.resolve()
    candidate = resolved_root
    for part in Path(normalized).parts:
        candidate /= part
        if candidate.is_symlink():
            raise OperationError("symlinks are not allowed in read-only config paths")
    resolved = candidate.resolve()
    if not resolved.is_relative_to(resolved_root):
        raise OperationError("path escapes the read-only config root")
    return resolved


def redact_yaml_text(content: str) -> tuple[str, int]:
    redacted_lines: list[str] = []
    redaction_count = 0
    for line in content.splitlines(keepends=True):
        ending = "\n" if line.endswith("\n") else ""
        body = line[:-1] if ending else line
        match = _SENSITIVE_YAML_LINE.match(body)
        if match and not match.group(2).lstrip().startswith("!secret"):
            body = f'{match.group(1)}"***REDACTED***"'
            redaction_count += 1
        body, url_count = _ABSOLUTE_URL.subn("***REDACTED_URL***", body)
        redaction_count += url_count
        redacted_lines.append(body + ending)
    return "".join(redacted_lines), redaction_count


def redact_structured_value(value: Any, key: str = "") -> tuple[Any, int]:
    if _SENSITIVE_KEY.search(key):
        return "***REDACTED***", 1
    if isinstance(value, dict):
        clean: dict[str, Any] = {}
        count = 0
        for child_key, child_value in value.items():
            redacted, child_count = redact_structured_value(child_value, str(child_key))
            clean[str(child_key)] = redacted
            count += child_count
        return clean, count
    if isinstance(value, list):
        clean_list = []
        count = 0
        for child in value:
            redacted, child_count = redact_structured_value(child)
            clean_list.append(redacted)
            count += child_count
        return clean_list, count
    if isinstance(value, str):
        redacted, count = _ABSOLUTE_URL.subn("***REDACTED_URL***", value)
        return redacted, count
    return value, 0


def _entity_id(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 255 or not _ENTITY_ID.fullmatch(value):
        raise OperationError("entity_id has an invalid format")
    return value


def _pattern(value: Any, name: str, pattern: re.Pattern[str], maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or not pattern.fullmatch(value):
        raise OperationError(f"{name} has an invalid format")
    return value


def _bounded_int(value: Any, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise OperationError(f"{name} must be an integer from {minimum} to {maximum}")
    return value
