from __future__ import annotations

import json
import logging
import os
import ssl
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
import websocket

from operations import OperationError, ensure_result_size, matches_entity_query, validate_operation

HA_API_URL = "http://supervisor/core/api"
HA_WS_URL = "ws://supervisor/core/websocket"
OPTIONS_PATH = Path("/data/options.json")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
LOGGER = logging.getLogger("ha-cloud-connector")


class HomeAssistantClient:
    def __init__(self, token: str, timeout: float) -> None:
        self._token = token
        self._timeout = timeout
        self._http = httpx.Client(
            base_url=HA_API_URL,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            timeout=timeout,
        )

    def close(self) -> None:
        self._http.close()

    def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        response = self._http.get(path, params=params)
        response.raise_for_status()
        try:
            return response.json()
        except json.JSONDecodeError as exc:
            raise OperationError("Home Assistant returned a non-JSON response") from exc

    def get_optional(self, path: str) -> Any | None:
        response = self._http.get(path)
        if response.status_code == 404:
            return None
        response.raise_for_status()
        try:
            return response.json()
        except json.JSONDecodeError as exc:
            raise OperationError("Home Assistant returned a non-JSON response") from exc

    def websocket_command(self, message: dict[str, Any]) -> Any:
        ws = websocket.create_connection(
            HA_WS_URL,
            timeout=self._timeout,
            sslopt={"cert_reqs": ssl.CERT_NONE},
        )
        try:
            initial = _receive_json(ws)
            if initial.get("type") != "auth_required":
                raise OperationError("unexpected Home Assistant WebSocket handshake")
            ws.send(json.dumps({"type": "auth", "access_token": self._token}))
            auth = _receive_json(ws)
            if auth.get("type") != "auth_ok":
                raise OperationError("Home Assistant WebSocket authentication failed")
            request_id = 1
            ws.send(json.dumps({"id": request_id, **message}))
            while True:
                response = _receive_json(ws)
                if response.get("id") != request_id:
                    continue
                if response.get("type") != "result":
                    continue
                if not response.get("success", False):
                    error = response.get("error", {})
                    code = error.get("code", "unknown_error") if isinstance(error, dict) else "unknown_error"
                    raise OperationError(f"Home Assistant WebSocket request failed: {code}")
                return response.get("result")
        finally:
            ws.close()


class OperationExecutor:
    def __init__(self, client: HomeAssistantClient) -> None:
        self._ha = client

    def execute(self, operation: str, params: dict[str, Any]) -> Any:
        operation, params = validate_operation(operation, params)
        handlers = {
            "list_entities": self._list_entities,
            "get_state": self._get_state,
            "get_history": self._get_history,
            "get_logbook": self._get_logbook,
            "get_automation_config": self._get_automation_config,
            "get_automation_traces": self._get_automation_traces,
            "get_system_health": self._get_system_health,
        }
        result = handlers[operation](params)
        ensure_result_size(result)
        return result

    def _list_entities(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        states = self._ha.get("/states")
        if not isinstance(states, list):
            raise OperationError("Home Assistant states response has an invalid shape")
        domain = params.get("domain")
        query = params.get("query")
        selected = [
            state
            for state in states
            if isinstance(state, dict)
            and isinstance(state.get("entity_id"), str)
            and (domain is None or state["entity_id"].startswith(f"{domain}."))
            and (query is None or matches_entity_query(state, query))
        ][: params["max_results"]]
        return [_bounded_state(state) for state in selected]

    def _get_state(self, params: dict[str, Any]) -> dict[str, Any]:
        state = self._ha.get(f"/states/{quote(params['entity_id'], safe='._')}")
        if not isinstance(state, dict):
            raise OperationError("Home Assistant state response has an invalid shape")
        return _bounded_state(state)

    def _get_history(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        start, end = _time_window(params["hours"])
        result = self._ha.get(
            f"/history/period/{quote(start, safe=':-+.TZ')}",
            params={
                "end_time": end,
                "filter_entity_id": ",".join(params["entity_ids"]),
                "minimal_response": "",
                "no_attributes": "",
            },
        )
        if not isinstance(result, list):
            raise OperationError("Home Assistant history response has an invalid shape")
        remaining = params["max_results"]
        bounded: list[dict[str, Any]] = []
        for entity_id, series in zip(params["entity_ids"], result, strict=False):
            if remaining <= 0:
                break
            if isinstance(series, list):
                clipped = series[-remaining:]
                bounded.append({"entity_id": entity_id, "states": clipped})
                remaining -= len(clipped)
        return bounded

    def _get_logbook(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        start, end = _time_window(params["hours"])
        query: dict[str, Any] = {"end_time": end}
        if "entity_id" in params:
            query["entity"] = params["entity_id"]
        result = self._ha.get(f"/logbook/{quote(start, safe=':-+.TZ')}", params=query)
        if not isinstance(result, list):
            raise OperationError("Home Assistant logbook response has an invalid shape")
        return [entry for entry in result[-params["max_results"] :] if isinstance(entry, dict)]

    def _get_automation_config(self, params: dict[str, Any]) -> Any:
        automation_id = quote(self._resolve_automation_id(params["automation_id"]), safe="_-")
        return self._ha.get(f"/config/automation/config/{automation_id}")

    def _get_automation_traces(self, params: dict[str, Any]) -> list[Any]:
        result = self._ha.websocket_command(
            {
                "type": "trace/list",
                "domain": "automation",
                "item_id": self._resolve_automation_id(params["automation_id"]),
            }
        )
        if not isinstance(result, list):
            raise OperationError("Home Assistant trace response has an invalid shape")
        return result[: params["max_results"]]

    def _resolve_automation_id(self, candidate: str) -> str:
        state = self._ha.get_optional(f"/states/automation.{quote(candidate, safe='_')}")
        if isinstance(state, dict):
            attributes = state.get("attributes")
            config_id = attributes.get("id") if isinstance(attributes, dict) else None
            if isinstance(config_id, str) and config_id:
                return config_id
        return candidate

    def _get_system_health(self, params: dict[str, Any]) -> dict[str, Any]:
        config = self._ha.get("/config")
        if not isinstance(config, dict):
            raise OperationError("Home Assistant config response has an invalid shape")
        logs = self._ha.websocket_command({"type": "system_log/list"})
        if not isinstance(logs, list):
            logs = []
        selected_logs = []
        for entry in logs:
            if not isinstance(entry, dict) or str(entry.get("level", "")).upper() not in {"ERROR", "WARNING"}:
                continue
            selected_logs.append(
                {
                    key: entry[key]
                    for key in ("level", "name", "message", "timestamp", "count", "first_occurred")
                    if key in entry
                }
            )
        selected_config = {
            key: config[key]
            for key in (
                "version",
                "state",
                "location_name",
                "time_zone",
                "unit_system",
                "components",
                "safe_mode",
            )
            if key in config
        }
        if isinstance(selected_config.get("components"), list):
            selected_config["component_count"] = len(selected_config.pop("components"))
        return {
            "config": selected_config,
            "system_log": selected_logs[: params["max_log_entries"]],
        }


def _receive_json(ws: websocket.WebSocket) -> dict[str, Any]:
    raw = ws.recv()
    try:
        value = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as exc:
        raise OperationError("Home Assistant WebSocket returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise OperationError("Home Assistant WebSocket returned an invalid message")
    return value


def _time_window(hours: int) -> tuple[str, str]:
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)
    return start.isoformat(timespec="seconds"), end.isoformat(timespec="seconds")


def _bounded_state(state: dict[str, Any]) -> dict[str, Any]:
    return {
        key: state[key]
        for key in ("entity_id", "state", "attributes", "last_changed", "last_updated", "context")
        if key in state
    }


def load_options() -> dict[str, Any]:
    try:
        options = json.loads(OPTIONS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("unable to read valid add-on options from /data/options.json") from exc
    required = ("gateway_url", "instance_id", "connector_token")
    missing = [name for name in required if not isinstance(options.get(name), str) or not options[name].strip()]
    if missing:
        raise RuntimeError(f"missing required add-on option: {missing[0]}")
    options["gateway_url"] = options["gateway_url"].rstrip("/")
    options["poll_interval_seconds"] = _option_number(options, "poll_interval_seconds", 2, 1, 60)
    options["request_timeout_seconds"] = _option_number(options, "request_timeout_seconds", 30, 5, 120)
    if not isinstance(options.get("verify_ssl", True), bool):
        raise RuntimeError("verify_ssl must be true or false")
    options["verify_ssl"] = options.get("verify_ssl", True)
    return options


def _option_number(options: dict[str, Any], name: str, default: int, minimum: int, maximum: int) -> int:
    value = options.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise RuntimeError(f"{name} must be an integer from {minimum} to {maximum}")
    return value


def run() -> None:
    options = load_options()
    supervisor_token = os.environ.get("SUPERVISOR_TOKEN")
    if not supervisor_token:
        raise RuntimeError("SUPERVISOR_TOKEN is unavailable; homeassistant_api must be enabled")

    headers = {"Authorization": f"Bearer {options['connector_token']}"}
    timeout = httpx.Timeout(options["request_timeout_seconds"])
    gateway = httpx.Client(
        base_url=options["gateway_url"],
        headers=headers,
        timeout=timeout,
        verify=options["verify_ssl"],
    )
    ha = HomeAssistantClient(supervisor_token, options["request_timeout_seconds"])
    executor = OperationExecutor(ha)
    LOGGER.info("Connector started for configured instance")
    try:
        while True:
            try:
                response = gateway.get("/api/connector/commands", params={"instance_id": options["instance_id"]})
                if response.status_code == 204:
                    time.sleep(options["poll_interval_seconds"])
                    continue
                response.raise_for_status()
                command = response.json()
                if not isinstance(command, dict):
                    raise OperationError("gateway returned an invalid command")
                command_id = command.get("command_id")
                if not isinstance(command_id, str):
                    raise OperationError("gateway returned a command without a valid command_id")
                try:
                    result = executor.execute(command.get("operation"), command.get("params"))
                    completion = {"status": "succeeded", "result": result}
                except (OperationError, httpx.HTTPError, websocket.WebSocketException) as exc:
                    LOGGER.warning("Command %s failed (%s)", command_id, type(exc).__name__)
                    completion = {"status": "failed", "error": str(exc)[:1024]}
                result_response = gateway.post(
                    f"/api/connector/commands/{quote(command_id, safe='')}/result",
                    params={"instance_id": options["instance_id"]},
                    json=completion,
                )
                if result_response.status_code == 409:
                    LOGGER.info("Command %s completed after its claim was no longer active", command_id)
                    continue
                result_response.raise_for_status()
            except (httpx.HTTPError, json.JSONDecodeError, OperationError) as exc:
                LOGGER.warning("Gateway poll failed (%s)", type(exc).__name__)
                time.sleep(options["poll_interval_seconds"])
    finally:
        ha.close()
        gateway.close()


if __name__ == "__main__":
    run()
