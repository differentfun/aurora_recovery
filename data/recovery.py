"""Recovery helpers for extracting files from scan results."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, Optional

from .config import DEFAULT_RECOVERY_DIR
from .models import CarvedMatch, ResultKind, ScanResult
from .utils import copy_binary_range, copy_file, ensure_directory, generate_identifier


def sanitize_filename(name: str) -> str:
    sanitized = re.sub(r"[^a-zA-Z0-9._-]+", "_", name).strip("._")
    return sanitized or "recovered"


class RecoveryManager:
    """Perform recovery operations for discovered items."""

    def __init__(self, *, default_directory: Optional[Path] = None) -> None:
        self.default_directory = ensure_directory(default_directory or DEFAULT_RECOVERY_DIR)
        self._fs_handlers: Dict[str, object] = {}
    def register_filesystem(self, name: str, handler: object) -> None:
        if not name:
            return
        key = name.lower()
        self._fs_handlers[key] = handler
        if key.startswith("fat"):
            self._fs_handlers.setdefault("fat", handler)
        if key.startswith("ext"):
            self._fs_handlers.setdefault("ext", handler)
        if key.startswith("hfs") or key.startswith("apple"):
            self._fs_handlers.setdefault("hfs", handler)
        if key.startswith("apfs"):
            self._fs_handlers.setdefault("apfs", handler)


    def recover_scan_result(
        self,
        result: ScanResult,
        *,
        destination_dir: Optional[Path] = None,
        overwrite: bool = False,
    ) -> Path:
        target_dir = ensure_directory(destination_dir or self.default_directory)
        base_name = sanitize_filename(result.display_name)
        dest_path = self._unique_destination(target_dir, base_name)
        if result.kind == ResultKind.CARVED:
            raise ValueError("Use recover_carved_match for carved segments")

        metadata = getattr(result, "metadata", {}) or {}
        filesystem = metadata.get("filesystem")
        if filesystem:
            handler = self._fs_handlers.get(filesystem.lower())
            if not handler:
                raise ValueError(f"No handler registered for filesystem: {filesystem}")
            record_id = metadata.get("filesystem_record")
            if record_id is None:
                raise ValueError("Missing filesystem record reference")
            self._recover_filesystem(handler, record_id, dest_path, overwrite=overwrite)
            return dest_path

        return copy_file(result.location, dest_path, overwrite=overwrite)
    def _recover_filesystem(self, handler: object, record_id: str, destination: Path, overwrite: bool) -> None:
        ensure_directory(destination.parent)
        if destination.exists() and not overwrite:
            raise FileExistsError(f"Destination file already exists: {destination}")
        if hasattr(handler, "recover_record"):
            handler.recover_record(int(record_id), destination, overwrite=overwrite)
        else:
            raise ValueError("Filesystem handler does not support recovery")


    def recover_carved_match(
        self,
        match: CarvedMatch,
        *,
        destination_dir: Optional[Path] = None,
        overwrite: bool = False,
    ) -> Path:
        target_dir = ensure_directory(destination_dir or self.default_directory)
        suffix = match.signature.extension or ""
        base_name = sanitize_filename(f"{match.signature.name}_{match.identifier}")
        dest_path = self._unique_destination(target_dir, base_name + suffix)
        return copy_binary_range(
            match.source,
            dest_path,
            start=match.offset_start,
            end=match.offset_end,
            overwrite=overwrite,
        )

    def _unique_destination(self, directory: Path, base_name: str) -> Path:
        directory = ensure_directory(directory)
        candidate = directory / base_name
        if not candidate.exists():
            return candidate
        stem = candidate.stem
        suffix = candidate.suffix
        counter = 1
        while True:
            new_name = f"{stem}_{counter}{suffix}"
            candidate = directory / new_name
            if not candidate.exists():
                return candidate
            counter += 1

    def prepare_job_directory(self) -> Path:
        job_dir = self.default_directory / generate_identifier("job")
        return ensure_directory(job_dir)
