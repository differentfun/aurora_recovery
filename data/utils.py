"""Utility helpers used across the Aurora Recover application."""
from __future__ import annotations

import os
import shutil
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable, Optional


def format_bytes(size: int) -> str:
    """Human friendly file size formatting."""
    negative = size < 0
    size = abs(size)
    units = ["B", "KB", "MB", "GB", "TB"]
    for unit in units:
        if size < 1024 or unit == units[-1]:
            value = size if unit == "B" else size / 1024
            formatted = f"{value:.1f}{unit}" if unit != "B" else f"{value}{unit}"
            return f"-{formatted}" if negative else formatted
        size /= 1024
    return f"-{size:.1f}PB" if negative else f"{size:.1f}PB"


def format_timestamp(value: Optional[datetime]) -> str:
    if value is None:
        return "Unknown"
    return value.strftime("%Y-%m-%d %H:%M:%S")


def generate_identifier(prefix: str) -> str:
    token = uuid.uuid4().hex[:10]
    return f"{prefix}-{token}"


def ensure_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def copy_file(source: Path, destination: Path, overwrite: bool = False) -> Path:
    if destination.exists() and not overwrite:
        raise FileExistsError(f"Destination file already exists: {destination}")
    ensure_directory(destination.parent)
    return Path(shutil.copy2(source, destination))


def copy_binary_range(
    source: Path,
    destination: Path,
    start: int,
    end: int,
    chunk_size: int = 1024 * 1024,
    overwrite: bool = False,
) -> Path:
    if destination.exists() and not overwrite:
        raise FileExistsError(f"Destination file already exists: {destination}")
    ensure_directory(destination.parent)
    total = end - start
    copied = 0
    with source.open("rb") as src, destination.open("wb") as dst:
        src.seek(start)
        remaining = total
        while remaining > 0:
            chunk = src.read(min(chunk_size, remaining))
            if not chunk:
                break
            dst.write(chunk)
            copied += len(chunk)
            remaining -= len(chunk)
    if copied != total:
        raise IOError(f"Copied {copied} bytes but expected {total}")
    return destination


def read_preview(path: Path, size: int = 256) -> bytes:
    with path.open("rb") as handle:
        return handle.read(size)


def is_display_available() -> bool:
    if os.name == "nt":
        return True  # Windows typically provides a display context
    return bool(os.environ.get("DISPLAY"))


class ThreadedTask:
    """Helper wrapper for running callables in background threads."""

    def __init__(self, func: Callable, *args, **kwargs) -> None:
        self.func = func
        self.args = args
        self.kwargs = kwargs
        self._thread: Optional[threading.Thread] = None
        self.result = None
        self.error: Optional[BaseException] = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            raise RuntimeError("Thread already running")

        def _target() -> None:
            try:
                self.result = self.func(*self.args, **self.kwargs)
            except BaseException as exc:  # noqa: BLE001 - capture all errors
                self.error = exc

        self._thread = threading.Thread(target=_target, daemon=True)
        self._thread.start()

    def join(self, timeout: Optional[float] = None) -> None:
        if not self._thread:
            return
        self._thread.join(timeout)

    @property
    def done(self) -> bool:
        return bool(self._thread and not self._thread.is_alive())
