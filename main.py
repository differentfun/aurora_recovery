"""Launcher for the Aurora Recover utility."""
from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="aurora-recover",
        description="Prototype utility for scanning storage targets and preparing data recovery jobs.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Run a short self-check instead of launching the GUI.",
    )
    return parser.parse_args(argv)


def run_self_check() -> int:
    """Run a quick import and diagnostics routine used in CI/headless environments."""
    from data.scanner import ScannerEngine
    from data.config import DEFAULT_SIGNATURES

    engine = ScannerEngine(signatures=DEFAULT_SIGNATURES)
    # Run a minimal check to ensure the scanner can enumerate targets without crashing.
    try:
        engine.list_quick_targets()
    except Exception as exc:  # pragma: no cover - should never happen
        print(f"Self-check failed while enumerating targets: {exc}", file=sys.stderr)
        return 1
    return 0


def _ensure_privileged(raw_args: list[str]) -> None:
    """Request elevated privileges via pkexec when running on Linux."""

    if os.environ.get("AURORA_PRIV_ELEVATED") == "1":
        return
    geteuid = getattr(os, "geteuid", None)
    if callable(geteuid) and geteuid() == 0:
        os.environ["AURORA_PRIV_ELEVATED"] = "1"
        return
    if os.name != "posix":
        return
    if any(arg == "--check" for arg in raw_args):
        return
    pkexec_path = shutil.which("pkexec")
    if not pkexec_path:
        return
    script_path = Path(__file__).resolve()
    env_cmd = shutil.which("env") or "/usr/bin/env"
    env_assignments: list[str] = []
    for key in ("DISPLAY", "XAUTHORITY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"):
        value = os.environ.get(key)
        if value:
            env_assignments.append(f"{key}={value}")
    env_assignments.append("AURORA_PRIV_ELEVATED=1")
    command = [pkexec_path, env_cmd, *env_assignments, sys.executable, str(script_path), *raw_args]
    try:
        os.execvp(pkexec_path, command)
    except OSError as exc:  # pragma: no cover - best effort escalation
        print(f"Failed to escalate privileges via pkexec: {exc}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    raw_args = list(sys.argv[1:] if argv is None else argv)
    _ensure_privileged(raw_args)
    args = parse_args(raw_args)
    if args.check:
        return run_self_check()

    from data.controller import AppController

    controller = AppController()
    return controller.run()


if __name__ == "__main__":
    raise SystemExit(main())
