#!/usr/bin/env python3
"""Anchoring configuration loader for ADR-015 runtime policy.

Resolution precedence:
1. Built-in defaults
2. `anchoring.toml`
3. Environment variables
4. CLI overrides

This module is intentionally conservative: missing or malformed values do not
crash at load-time. Callers apply strict/warn policy at execution time.
"""

from __future__ import annotations

import os
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = REPO_ROOT / "anchoring.toml"

WARN = "warn"
STRICT = "strict"
ALLOWED_POLICY_MODES = {WARN, STRICT}


@dataclass(slots=True, frozen=True)
class OtsConfig:
    enabled: bool = True
    calendar_urls: list[str] = field(default_factory=list)


@dataclass(slots=True, frozen=True)
class TsaConfig:
    enabled: bool = False
    url: str = ""
    ca_bundle: str = ""
    chain_bundle: str = ""
    policy_oid: str = ""
    timeout_s: float = 30.0
    verify: bool = False


@dataclass(slots=True, frozen=True)
class PeersConfig:
    enabled: bool = False
    config_path: str = ""
    min_signatures: int = 1
    context: str = "trackone:day-root:v1"


@dataclass(slots=True, frozen=True)
class PolicyConfig:
    mode: str = WARN


@dataclass(slots=True, frozen=True)
class AnchoringConfig:
    path: Path
    ots: OtsConfig
    tsa: TsaConfig
    peers: PeersConfig
    policy: PolicyConfig


def _as_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, int):
        return value != 0
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    return default


def _as_float(value: Any, default: float) -> float:
    if value is None:
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _as_int(value: Any, default: int) -> int:
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_str(value: Any, default: str) -> str:
    if value is None:
        return default
    return str(value).strip()


def _as_csv_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    text = str(value).strip()
    if not text:
        return []
    return [part.strip() for part in text.split(",") if part.strip()]


def _read_toml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("rb") as f:
        data = tomllib.load(f)
    if isinstance(data, dict):
        return data
    return {}


def _pick(
    *,
    file_value: Any,
    env: Mapping[str, str],
    env_keys: list[str],
    cli: Mapping[str, Any] | None,
    cli_key: str | None = None,
) -> Any:
    value = file_value
    for key in env_keys:
        if key in env and env.get(key, "").strip() != "":
            value = env[key]
    if cli_key and cli and cli.get(cli_key) is not None:
        value = cli[cli_key]
    return value


def _safe_mode(value: Any, default: str = WARN) -> str:
    mode = _as_str(value, default).lower()
    if mode not in ALLOWED_POLICY_MODES:
        return default
    return mode


def load_anchoring_config(
    *,
    config_path: Path | None = None,
    env: Mapping[str, str] | None = None,
    cli_overrides: Mapping[str, Any] | None = None,
) -> AnchoringConfig:
    """Load anchoring configuration with precedence file < env < CLI."""
    env_map = env or os.environ
    path = config_path or DEFAULT_CONFIG_PATH
    raw = _read_toml(path)

    ots_raw = raw.get("ots", {}) if isinstance(raw.get("ots", {}), dict) else {}
    tsa_raw = raw.get("tsa", {}) if isinstance(raw.get("tsa", {}), dict) else {}
    peers_raw = raw.get("peers", {}) if isinstance(raw.get("peers", {}), dict) else {}
    policy_raw = (
        raw.get("policy", {}) if isinstance(raw.get("policy", {}), dict) else {}
    )

    ots_enabled = _as_bool(
        _pick(
            file_value=ots_raw.get("enabled"),
            env=env_map,
            env_keys=["ANCHOR_OTS_ENABLED"],
            cli=cli_overrides,
            cli_key="ots_enabled",
        ),
        True,
    )
    ots_calendars = _as_csv_list(
        _pick(
            file_value=ots_raw.get("calendar_urls"),
            env=env_map,
            env_keys=["ANCHOR_OTS_CALENDARS", "OTS_CALENDARS"],
            cli=cli_overrides,
            cli_key="ots_calendar_urls",
        )
    )

    tsa_enabled = _as_bool(
        _pick(
            file_value=tsa_raw.get("enabled"),
            env=env_map,
            env_keys=["ANCHOR_TSA_ENABLED"],
            cli=cli_overrides,
            cli_key="tsa_enabled",
        ),
        False,
    )
    tsa_url = _as_str(
        _pick(
            file_value=tsa_raw.get("url"),
            env=env_map,
            env_keys=["ANCHOR_TSA_URL", "PIPELINE_TSA_URL"],
            cli=cli_overrides,
            cli_key="tsa_url",
        ),
        "",
    )
    tsa_ca_bundle = _as_str(
        _pick(
            file_value=tsa_raw.get("ca_bundle"),
            env=env_map,
            env_keys=["ANCHOR_TSA_CA_BUNDLE"],
            cli=cli_overrides,
            cli_key="tsa_ca_bundle",
        ),
        "",
    )
    tsa_chain_bundle = _as_str(
        _pick(
            file_value=tsa_raw.get("chain_bundle"),
            env=env_map,
            env_keys=["ANCHOR_TSA_CHAIN_BUNDLE"],
            cli=cli_overrides,
            cli_key="tsa_chain_bundle",
        ),
        "",
    )
    tsa_policy_oid = _as_str(
        _pick(
            file_value=tsa_raw.get("policy_oid"),
            env=env_map,
            env_keys=["ANCHOR_TSA_POLICY_OID", "PIPELINE_TSA_POLICY_OID"],
            cli=cli_overrides,
            cli_key="tsa_policy_oid",
        ),
        "",
    )
    tsa_timeout_s = _as_float(
        _pick(
            file_value=tsa_raw.get("timeout_s"),
            env=env_map,
            env_keys=["ANCHOR_TSA_TIMEOUT", "PIPELINE_TSA_TIMEOUT"],
            cli=cli_overrides,
            cli_key="tsa_timeout_s",
        ),
        30.0,
    )
    tsa_verify = _as_bool(
        _pick(
            file_value=tsa_raw.get("verify"),
            env=env_map,
            env_keys=["ANCHOR_TSA_VERIFY"],
            cli=cli_overrides,
            cli_key="tsa_verify",
        ),
        False,
    )

    peers_enabled = _as_bool(
        _pick(
            file_value=peers_raw.get("enabled"),
            env=env_map,
            env_keys=["ANCHOR_PEERS_ENABLED"],
            cli=cli_overrides,
            cli_key="peers_enabled",
        ),
        False,
    )
    peers_config_path = _as_str(
        _pick(
            file_value=peers_raw.get("config_path"),
            env=env_map,
            env_keys=["ANCHOR_PEERS_CONFIG"],
            cli=cli_overrides,
            cli_key="peers_config_path",
        ),
        "",
    )
    peers_min_signatures = _as_int(
        _pick(
            file_value=peers_raw.get("min_signatures"),
            env=env_map,
            env_keys=["ANCHOR_PEERS_MIN", "PIPELINE_PEER_MIN"],
            cli=cli_overrides,
            cli_key="peers_min_signatures",
        ),
        1,
    )
    peers_context = _as_str(
        _pick(
            file_value=peers_raw.get("context"),
            env=env_map,
            env_keys=["ANCHOR_PEERS_CONTEXT", "PIPELINE_PEER_CONTEXT"],
            cli=cli_overrides,
            cli_key="peers_context",
        ),
        "trackone:day-root:v1",
    )

    policy_mode = _safe_mode(
        _pick(
            file_value=policy_raw.get("mode"),
            env=env_map,
            env_keys=["ANCHOR_POLICY_MODE", "PIPELINE_POLICY_MODE"],
            cli=cli_overrides,
            cli_key="policy_mode",
        )
    )

    return AnchoringConfig(
        path=path,
        ots=OtsConfig(enabled=ots_enabled, calendar_urls=ots_calendars),
        tsa=TsaConfig(
            enabled=tsa_enabled,
            url=tsa_url,
            ca_bundle=tsa_ca_bundle,
            chain_bundle=tsa_chain_bundle,
            policy_oid=tsa_policy_oid,
            timeout_s=tsa_timeout_s,
            verify=tsa_verify,
        ),
        peers=PeersConfig(
            enabled=peers_enabled,
            config_path=peers_config_path,
            min_signatures=max(1, peers_min_signatures),
            context=peers_context or "trackone:day-root:v1",
        ),
        policy=PolicyConfig(mode=policy_mode),
    )


def compute_overall_status(
    *,
    policy_mode: str,
    channels: Mapping[str, Mapping[str, Any]],
) -> str:
    """Reduce per-channel status into a single run status.

    `channels` expects mappings that contain:
    - `enabled`: bool
    - `status`: one of verified|failed|missing|pending|skipped
    """
    if policy_mode == STRICT:
        for item in channels.values():
            if item.get("enabled", False) and item.get("status") != "verified":
                return "failed"
        return "success"

    # warn-mode: OTS remains the integrity-critical channel when enabled.
    ots = channels.get("ots", {})
    if ots.get("enabled", False) and ots.get("status") in {"failed", "missing"}:
        return "failed"
    return "success"
