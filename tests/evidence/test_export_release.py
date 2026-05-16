from __future__ import annotations

from pathlib import Path


def test_export_release_wrapper_routes_to_rust_contract(
    tmp_path: Path, load_module, monkeypatch
) -> None:
    module = load_module(
        "export_release_wrapper_under_test",
        Path("scripts/evidence/export_release.py"),
    )
    captured: dict[str, object] = {}

    def fake_run(cmd, *, cwd, check, capture_output, text):
        captured["cmd"] = cmd
        captured["cwd"] = cwd
        captured["check"] = check
        captured["capture_output"] = capture_output
        captured["text"] = text

        class Proc:
            returncode = 0
            stdout = str(tmp_path / "evidence/site/test/day/2025-10-07") + "\n"
            stderr = ""

        return Proc()

    monkeypatch.setattr(module.subprocess, "run", fake_run)

    out = module.export_release(
        tmp_path / "pipeline",
        tmp_path / "evidence",
        site="test",
        day="2025-10-07",
        include_frames=True,
    )

    assert out == tmp_path / "evidence/site/test/day/2025-10-07"
    cmd = captured["cmd"]
    assert cmd[:7] == [
        "cargo",
        "run",
        "--quiet",
        "--package",
        "trackone-evidence",
        "--",
        "export",
    ]
    assert "--include-frames" in cmd
    assert captured["cwd"] == module.REPO_ROOT
    assert captured["check"] is False
    assert captured["capture_output"] is True
    assert captured["text"] is True
