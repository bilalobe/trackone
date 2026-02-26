from __future__ import annotations

from pathlib import Path

from scripts.gateway.anchoring_config import (
    STRICT,
    WARN,
    compute_overall_status,
    load_anchoring_config,
)


def test_load_defaults_when_config_missing(tmp_path: Path) -> None:
    cfg = load_anchoring_config(config_path=tmp_path / "missing.toml", env={})
    assert cfg.ots.enabled is True
    assert cfg.ots.calendar_urls == []
    assert cfg.tsa.enabled is False
    assert cfg.peers.enabled is False
    assert cfg.policy.mode == WARN


def test_precedence_file_then_env_then_cli(tmp_path: Path) -> None:
    cfg_file = tmp_path / "anchoring.toml"
    cfg_file.write_text(
        """
[ots]
enabled = false
calendar_urls = ["https://from-file.invalid"]

[policy]
mode = "warn"
""".strip()
        + "\n",
        encoding="utf-8",
    )

    env = {
        "ANCHOR_OTS_ENABLED": "1",
        "OTS_CALENDARS": "https://from-env.invalid",
        "ANCHOR_POLICY_MODE": "strict",
    }
    cli = {
        "ots_enabled": False,
        "ots_calendar_urls": ["https://from-cli.invalid"],
        "policy_mode": "warn",
    }
    cfg = load_anchoring_config(config_path=cfg_file, env=env, cli_overrides=cli)

    assert cfg.ots.enabled is False
    assert cfg.ots.calendar_urls == ["https://from-cli.invalid"]
    assert cfg.policy.mode == WARN


def test_legacy_env_aliases_are_supported(tmp_path: Path) -> None:
    cfg_file = tmp_path / "anchoring.toml"
    cfg_file.write_text("[tsa]\nenabled = true\n", encoding="utf-8")

    env = {
        "PIPELINE_TSA_URL": "https://tsa.example.invalid",
        "PIPELINE_TSA_TIMEOUT": "11.5",
        "PIPELINE_PEER_MIN": "3",
        "PIPELINE_PEER_CONTEXT": "ctx:legacy",
        "PIPELINE_POLICY_MODE": "strict",
    }
    cfg = load_anchoring_config(config_path=cfg_file, env=env)
    assert cfg.tsa.url == "https://tsa.example.invalid"
    assert cfg.tsa.timeout_s == 11.5
    assert cfg.peers.min_signatures == 3
    assert cfg.peers.context == "ctx:legacy"
    assert cfg.policy.mode == STRICT


def test_compute_overall_status_warn_and_strict() -> None:
    channels = {
        "ots": {"enabled": True, "status": "verified"},
        "tsa": {"enabled": True, "status": "missing"},
        "peers": {"enabled": True, "status": "failed"},
    }
    assert compute_overall_status(policy_mode=WARN, channels=channels) == "success"
    assert compute_overall_status(policy_mode=STRICT, channels=channels) == "failed"
