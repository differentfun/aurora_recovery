"""Scanning utilities used to discover recoverable artefacts."""
from __future__ import annotations

from collections import deque
import os
import platform
from stat import S_ISBLK, S_ISCHR
from threading import Event
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable, List, Optional, Tuple

from .fs import AppleFSAnalyzer, ExtAnalyzer, FATAnalyzer, NTFSAnalyzer
from .config import DEFAULT_SCAN_CHUNK_SIZE, DEFAULT_SIGNATURES, MAX_PREVIEW_BYTES
from .models import (
    CarvedMatch,
    DeepScanSummary,
    FilesystemContext,
    FileSignature,
    ProgressReport,
    ResultKind,
    ResultStatus,
    ScanMode,
    ScanResult,
    ScanTarget,
    TargetType,
)
from .utils import format_bytes, format_timestamp, generate_identifier

ProgressCallback = Callable[[ProgressReport], None]


class ScannerEngine:
    """High-level orchestrator for scanning operations."""

    def __init__(
        self,
        *,
        signatures: Optional[Iterable[FileSignature]] = None,
        chunk_size: int = DEFAULT_SCAN_CHUNK_SIZE,
        max_files: int = 8_000,
    ) -> None:
        self.signatures = list(signatures) if signatures is not None else list(DEFAULT_SIGNATURES)
        self.chunk_size = max(chunk_size, 256 * 1024)
        self.max_files = max_files

    # ---------------------------------------------------------------------
    # Target discovery helpers
    # ---------------------------------------------------------------------
    def list_quick_targets(self) -> List[ScanTarget]:
        targets: List[ScanTarget] = []
        seen_paths: set[Path] = set()

        def add_target(target: ScanTarget) -> None:
            try:
                resolved = target.path.resolve()
            except OSError:
                resolved = target.path
            if resolved in seen_paths:
                return
            seen_paths.add(resolved)
            targets.append(target)

        home = Path.home()
        add_target(
            ScanTarget(
                identifier=generate_identifier("target"),
                label="Home",
                path=home,
                target_type=TargetType.DIRECTORY,
                description="User home directory",
                is_writable=True,
            )
        )

        root_candidate = Path("/")
        if root_candidate.exists():
            add_target(
                ScanTarget(
                    identifier=generate_identifier("target"),
                    label="Root",
                    path=root_candidate,
                    target_type=TargetType.DIRECTORY,
                    description="Filesystem root",
                )
            )

        for mount_point in self._discover_mount_points():
            if mount_point == home:
                continue
            label = mount_point.name or str(mount_point)
            add_target(
                ScanTarget(
                    identifier=generate_identifier("target"),
                    label=label,
                    path=mount_point,
                    target_type=TargetType.DIRECTORY,
                    description=f"Mounted volume at {mount_point}",
                    is_writable=os.access(mount_point, os.W_OK),
                )
            )

        for device_target in self._discover_block_devices():
            add_target(device_target)

        return targets

    def list_trash_targets(self) -> List[ScanTarget]:
        targets: List[ScanTarget] = []
        home = Path.home()
        candidates = [
            home / ".local/share/Trash/files",
            home / ".local/share/Trash/info",
            home / ".Trash",
        ]
        if platform.system() == "Darwin":
            candidates.append(home / "Library" / "Caches" / "Trash")
        if platform.system() == "Windows":
            system_drive = os.environ.get("SystemDrive", "C:")
            candidates.extend([Path(system_drive) / "$Recycle.Bin"])

        added = set()
        for candidate in candidates:
            if candidate.exists() and candidate.is_dir():
                resolved = candidate.resolve()
                if resolved in added:
                    continue
                targets.append(
                    ScanTarget(
                        identifier=generate_identifier("trash"),
                        label=resolved.name or str(resolved),
                        path=resolved,
                        target_type=TargetType.TRASH,
                        description="Trash / recycle bin entries",
                    )
                )
                added.add(resolved)
        return targets

    def list_all_targets(self) -> List[ScanTarget]:
        return self.list_quick_targets() + self.list_trash_targets()

    # ---------------------------------------------------------------------
    # Scan routines
    # ---------------------------------------------------------------------
    def quick_scan(
        self,
        target_path: Path,
        *,
        recursive: bool = True,
        progress_cb: Optional[ProgressCallback] = None,
        cancel_event: Optional[Event] = None,
    ) -> List[ScanResult]:
        """Perform a filesystem walk to catalog files within a directory."""
        if not target_path.exists() or not target_path.is_dir():
            raise FileNotFoundError(f"Target path not accessible: {target_path}")

        results: List[ScanResult] = []
        scanned_files = 0

        walker: Iterable[tuple[str, list[str], list[str]]]
        if recursive:
            walker = os.walk(target_path)
        else:
            # emulate non-recursive walk by listing once
            dirs = []
            files = []
            for entry in target_path.iterdir():
                if entry.is_dir():
                    dirs.append(entry.name)
                else:
                    files.append(entry.name)
            walker = [(str(target_path), dirs, files)]

        for root, _, files in walker:
            if cancel_event and cancel_event.is_set():
                break
            for filename in files:
                if cancel_event and cancel_event.is_set():
                    break
                file_path = Path(root) / filename
                try:
                    stat = file_path.stat()
                except (FileNotFoundError, PermissionError):
                    continue

                result = ScanResult(
                    identifier=generate_identifier("quick"),
                    display_name=filename,
                    location=file_path,
                    size_bytes=stat.st_size,
                    modified_at=datetime.fromtimestamp(stat.st_mtime),
                    status=ResultStatus.ANALYZED,
                    kind=ResultKind.EXISTING,
                    origin=ScanMode.QUICK,
                    metadata={
                        "size": format_bytes(stat.st_size),
                        "modified": format_timestamp(datetime.fromtimestamp(stat.st_mtime)),
                        "path": str(file_path),
                    },
                )
                results.append(result)
                scanned_files += 1

                if progress_cb:
                    ratio = min(scanned_files / self.max_files, 0.99)
                    progress_cb(
                        ProgressReport(
                            message=f"Analysed {scanned_files} files", ratio=ratio, detail=result.display_name
                        )
                    )

                if scanned_files >= self.max_files:
                    if progress_cb:
                        progress_cb(
                            ProgressReport(
                                message=f"Reached cap of {self.max_files} files", ratio=1.0, detail="Partial results"
                            )
                        )
                    return results

        if progress_cb:
            progress_cb(
                ProgressReport(
                    message=f"Scan complete: {len(results)} entries", ratio=1.0, detail="Quick scan"
                )
            )
        return results

    def trash_scan(
        self,
        target_path: Path,
        *,
        progress_cb: Optional[ProgressCallback] = None,
        cancel_event: Optional[Event] = None,
    ) -> List[ScanResult]:
        if not target_path.exists() or not target_path.is_dir():
            raise FileNotFoundError(f"Trash path not accessible: {target_path}")

        results: List[ScanResult] = []
        entries = list(target_path.glob("**/*"))
        total = len(entries) or 1
        for idx, entry in enumerate(entries, start=1):
            if cancel_event and cancel_event.is_set():
                break
            if not entry.is_file():
                continue
            try:
                stat = entry.stat()
            except (FileNotFoundError, PermissionError):
                continue

            result = ScanResult(
                identifier=generate_identifier("trash"),
                display_name=entry.name,
                location=entry,
                size_bytes=stat.st_size,
                modified_at=datetime.fromtimestamp(stat.st_mtime),
                status=ResultStatus.RECOVERABLE,
                kind=ResultKind.TRASH_ITEM,
                origin=ScanMode.TRASH,
                metadata={
                    "size": format_bytes(stat.st_size),
                    "path": str(entry),
                    "modified": format_timestamp(datetime.fromtimestamp(stat.st_mtime)),
                },
            )
            results.append(result)

            if progress_cb:
                progress_cb(
                    ProgressReport(
                        message=f"Indexed {idx}/{total} trash entries",
                        ratio=min(idx / total, 1.0),
                        detail=entry.name,
                    )
                )

        if progress_cb:
            progress_cb(
                ProgressReport(
                    message=f"Trash scan complete: {len(results)} recoverable items",
                    ratio=1.0,
                    detail="Trash scan",
                )
            )
        return results

    def deep_scan(
        self,
        image_path: Path,
        *,
        progress_cb: Optional[ProgressCallback] = None,
        cancel_event: Optional[Event] = None,
        signatures: Optional[Iterable[FileSignature]] = None,
        filesystem: Optional[str] = None,
    ) -> DeepScanSummary:
        """Perform a streaming signature-based carving pass over a binary image.

        The method reads the target image in bounded chunks so that very large
        files do not need to be loaded entirely into memory.
        """

        try:
            stat_result = image_path.stat()
        except OSError as exc:
            raise FileNotFoundError(f"Image path not accessible: {image_path}") from exc

        is_regular = image_path.is_file()
        is_block = S_ISBLK(stat_result.st_mode)
        is_char = S_ISCHR(stat_result.st_mode)
        if not (is_regular or is_block or is_char):
            raise FileNotFoundError(f"Image path not accessible: {image_path}")

        file_size = max(stat_result.st_size, 1)
        signature_list = list(signatures) if signatures is not None else list(self.signatures)
        filesystem_entries: List[ScanResult] = []
        context: Optional[FilesystemContext] = None

        if filesystem:
            fs_value = filesystem.lower()
            if fs_value == "ntfs":
                filesystem_entries, analyzer = self._scan_ntfs(
                    image_path, cancel_event=cancel_event, progress_cb=progress_cb
                )
                if analyzer:
                    context = FilesystemContext(name="ntfs", handler=analyzer)
            elif fs_value in {"fat", "fat16", "fat32"}:
                filesystem_entries, analyzer = self._scan_fat(
                    image_path, cancel_event=cancel_event, progress_cb=progress_cb
                )
                if analyzer and analyzer.geometry:
                    actual_type = analyzer.geometry.fat_type
                    if fs_value in {"fat16", "fat32"} and actual_type != fs_value:
                        filesystem_entries = []
                        analyzer = None
                    else:
                        context = FilesystemContext(name=actual_type, handler=analyzer)
            elif fs_value in {"ext", "ext2", "ext3", "ext4"}:
                filesystem_entries, analyzer = self._scan_ext(
                    image_path, cancel_event=cancel_event, progress_cb=progress_cb
                )
                if analyzer and analyzer.geometry:
                    actual_type = analyzer.geometry.fs_type
                    if fs_value in {"ext2", "ext3", "ext4"} and actual_type != fs_value:
                        filesystem_entries = []
                        analyzer = None
                    else:
                        context = FilesystemContext(name=actual_type, handler=analyzer)
            elif fs_value in {"apple", "hfs", "hfs+", "hfsplus", "apfs"}:
                filesystem_entries, analyzer = self._scan_hfs(
                    image_path, cancel_event=cancel_event, progress_cb=progress_cb
                )
                if analyzer:
                    fs_name = analyzer.filesystem_name or ("apfs" if fs_value == "apfs" else "hfs")
                    context = FilesystemContext(name=fs_name, handler=analyzer)
            if cancel_event and cancel_event.is_set():
                return DeepScanSummary(carved=[], filesystem_entries=filesystem_entries, context=context)

        matches: List[CarvedMatch] = []
        signature_count = len(signature_list) or 1

        for index, signature in enumerate(signature_list, start=1):
            if cancel_event and cancel_event.is_set():
                break
            base_ratio = (index - 1) / signature_count
            ratio_span = 1.0 / signature_count
            signature_matches = self._deep_scan_signature(
                image_path=image_path,
                signature=signature,
                file_size=file_size,
                base_ratio=base_ratio,
                ratio_span=ratio_span,
                progress_cb=progress_cb,
                cancel_event=cancel_event,
            )
            matches.extend(signature_matches)
            if cancel_event and cancel_event.is_set():
                break

        if progress_cb:
            if cancel_event and cancel_event.is_set():
                progress_cb(
                    ProgressReport(
                        message="Deep scan cancelled",
                        ratio=1.0,
                        detail=image_path.name,
                    )
                )
            else:
                progress_cb(
                    ProgressReport(
                        message=f"Deep scan complete: {len(matches)} carved segments",
                        ratio=1.0,
                        detail=image_path.name,
                    )
                )
        return DeepScanSummary(carved=matches, filesystem_entries=filesystem_entries, context=context)

    def _deep_scan_signature(
        self,
        *,
        image_path: Path,
        signature: FileSignature,
        file_size: int,
        base_ratio: float,
        ratio_span: float,
        progress_cb: Optional[ProgressCallback],
        cancel_event: Optional[Event],
    ) -> List[CarvedMatch]:
        header = signature.header
        footer = signature.footer or b""
        header_len = len(header)
        footer_len = len(footer)
        carry_len = max(header_len, footer_len) - 1 if max(header_len, footer_len) > 0 else 0
        pending_headers: deque[int] = deque()
        emitted_headers: set[int] = set()
        segments: List[tuple[int, int]] = []
        consumed = 0
        leftover = b""
        header_only = footer_len == 0

        with image_path.open("rb") as stream:
            while True:
                if cancel_event and cancel_event.is_set():
                    break
                chunk = stream.read(self.chunk_size)
                if not chunk:
                    break
                data = leftover + chunk
                data_start = consumed - len(leftover)
                events: List[tuple[str, int]] = []

                search_pos = 0
                while True:
                    idx = data.find(header, search_pos)
                    if idx == -1:
                        break
                    events.append(("header", idx))
                    search_pos = idx + 1

                if not header_only:
                    search_pos = 0
                    while True:
                        idx = data.find(footer, search_pos)
                        if idx == -1:
                            break
                        events.append(("footer", idx))
                        search_pos = idx + 1

                events.sort(key=lambda item: item[1])

                for kind, relative_pos in events:
                    if cancel_event and cancel_event.is_set():
                        break
                    absolute_pos = data_start + relative_pos
                    if header_only:
                        if kind == "header" and absolute_pos not in emitted_headers:
                            end_offset = min(absolute_pos + MAX_PREVIEW_BYTES, file_size)
                            if end_offset > absolute_pos:
                                segments.append((absolute_pos, end_offset))
                                emitted_headers.add(absolute_pos)
                    else:
                        if kind == "header":
                            pending_headers.append(absolute_pos)
                        elif pending_headers:
                            start_offset = pending_headers.popleft()
                            end_offset = absolute_pos + footer_len
                            if end_offset > start_offset:
                                segments.append((start_offset, end_offset))

                consumed += len(chunk)
                if cancel_event and cancel_event.is_set():
                    break
                if carry_len > 0:
                    if len(data) > carry_len:
                        leftover = data[-carry_len:]
                    else:
                        leftover = data
                else:
                    leftover = b""

                if progress_cb and not (cancel_event and cancel_event.is_set()):
                    processed_ratio = consumed / file_size
                    ratio = base_ratio + processed_ratio * ratio_span
                    if ratio >= 1.0:
                        ratio = 0.99
                    progress_cb(
                        ProgressReport(
                            message=f"Scanning {signature.name}",
                            ratio=ratio,
                            detail=f"Matches: {len(segments)}",
                        )
                    )

        matches: List[CarvedMatch] = []
        for start_offset, end_offset in segments:
            if cancel_event and cancel_event.is_set():
                break
            match_length = end_offset - start_offset
            preview = self._read_preview(image_path, start_offset, match_length)
            matches.append(
                CarvedMatch(
                    identifier=generate_identifier("carve"),
                    source=image_path,
                    signature=signature,
                    offset_start=start_offset,
                    offset_end=end_offset,
                    size_bytes=end_offset - start_offset,
                    preview=preview,
                )
            )
        return matches
    def _scan_ntfs(
        self,
        image_path: Path,
        *,
        cancel_event: Optional[Event],
        progress_cb: Optional[ProgressCallback],
    ) -> Tuple[List[ScanResult], Optional[NTFSAnalyzer]]:
        try:
            analyzer = NTFSAnalyzer(image_path)
            entries = analyzer.scan(cancel_event=cancel_event, progress_cb=progress_cb)
            return entries, analyzer
        except Exception:
            return [], None

    def _scan_fat(
        self,
        image_path: Path,
        *,
        cancel_event: Optional[Event],
        progress_cb: Optional[ProgressCallback],
    ) -> Tuple[List[ScanResult], Optional[FATAnalyzer]]:
        try:
            analyzer = FATAnalyzer(image_path)
            entries = analyzer.scan(cancel_event=cancel_event, progress_cb=progress_cb, limit=self.max_files)
            return entries, analyzer
        except Exception:
            return [], None

    def _scan_ext(
        self,
        image_path: Path,
        *,
        cancel_event: Optional[Event],
        progress_cb: Optional[ProgressCallback],
    ) -> Tuple[List[ScanResult], Optional[ExtAnalyzer]]:
        try:
            analyzer = ExtAnalyzer(image_path)
            entries = analyzer.scan(cancel_event=cancel_event, progress_cb=progress_cb, limit=self.max_files)
            return entries, analyzer
        except Exception:
            return [], None

    def _scan_hfs(
        self,
        image_path: Path,
        *,
        cancel_event: Optional[Event],
        progress_cb: Optional[ProgressCallback],
    ) -> Tuple[List[ScanResult], Optional[AppleFSAnalyzer]]:
        try:
            analyzer = AppleFSAnalyzer(image_path)
            entries = analyzer.scan(cancel_event=cancel_event, progress_cb=progress_cb, limit=self.max_files)
            return entries, analyzer
        except Exception:
            return [], None


    def _read_preview(self, image_path: Path, start_offset: int, length: int) -> bytes:
        limit = min(length, MAX_PREVIEW_BYTES)
        with image_path.open("rb") as stream:
            stream.seek(start_offset)
            return stream.read(limit)

    def _discover_block_devices(self) -> List[ScanTarget]:
        devices: List[ScanTarget] = []
        system = platform.system()

        if system in {"Linux", "FreeBSD"}:
            devices.extend(self._discover_block_devices_posix(Path("/sys/block")))
        elif system == "Darwin":
            dev_dir = Path("/dev")
            if dev_dir.exists():
                for entry in sorted(dev_dir.glob("disk*")):
                    try:
                        exists = entry.exists()
                    except OSError:
                        continue
                    if not exists:
                        continue
                    path = entry
                    devices.append(
                        ScanTarget(
                            identifier=generate_identifier("device"),
                            label=path.name,
                            path=path,
                            target_type=TargetType.DEVICE,
                            description="Physical disk",
                            is_writable=os.access(path, os.W_OK),
                            metadata={
                                "device_model": "Unknown",
                                "size_bytes": "0",
                                "is_partition": "0",
                            },
                        )
                    )
        # Windows and other platforms fall back to mount point enumeration.
        return devices

    def _discover_block_devices_posix(self, sys_block: Path) -> List[ScanTarget]:
        devices: List[ScanTarget] = []
        dev_dir = Path("/dev")
        if not sys_block.exists() or not dev_dir.exists():
            return devices

        def read_sys_value(path: Path) -> str:
            try:
                return path.read_text().strip()
            except OSError:
                return ""

        for entry in sorted(sys_block.iterdir()):
            name = entry.name
            if name.startswith(("loop", "ram", "fd")):
                continue
            device_path = dev_dir / name
            if not device_path.exists():
                continue

            raw_sectors = read_sys_value(entry / "size")
            size_bytes = 0
            if raw_sectors.isdigit():
                size_bytes = int(raw_sectors) * 512
            model = read_sys_value(entry / "device" / "model") or "Unknown"
            disk_id = generate_identifier("device")
            disk_target = ScanTarget(
                identifier=disk_id,
                label=device_path.name,
                path=device_path,
                target_type=TargetType.DEVICE,
                description=f"Physical disk ({format_bytes(size_bytes)})",
                is_writable=os.access(device_path, os.W_OK),
                metadata={
                    "device_model": model,
                    "size_bytes": str(size_bytes),
                    "is_partition": "0",
                },
            )
            devices.append(disk_target)

            for part in sorted(entry.glob(f"{name}*")):
                if part.name == name:
                    continue
                part_path = dev_dir / part.name
                if not part_path.exists():
                    continue
                raw_part_sectors = read_sys_value(part / "size")
                part_size_bytes = 0
                if raw_part_sectors.isdigit():
                    part_size_bytes = int(raw_part_sectors) * 512
                devices.append(
                    ScanTarget(
                        identifier=generate_identifier("device"),
                        label=part_path.name,
                        path=part_path,
                        target_type=TargetType.DEVICE,
                        description=f"Partition of /dev/{name} ({format_bytes(part_size_bytes)})",
                        is_writable=os.access(part_path, os.W_OK),
                        metadata={
                            "device_model": model,
                            "size_bytes": str(part_size_bytes),
                            "is_partition": "1",
                            "parent_id": disk_id,
                        },
                    )
                )
        return devices

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _discover_mount_points(self) -> List[Path]:
        points: List[Path] = []
        system = platform.system()

        if system == "Windows":
            import string
            from ctypes import windll

            bitmask = windll.kernel32.GetLogicalDrives()
            for letter in string.ascii_uppercase:
                if bitmask & 1:
                    drive = Path(f"{letter}:/")
                    if drive.exists():
                        points.append(drive)
                bitmask >>= 1
        else:
            potential = [Path("/Volumes"), Path("/mnt"), Path("/media"), Path("/run/media")]  # noqa: RUF100
            for base in potential:
                if base.exists():
                    for entry in base.iterdir():
                        if entry.is_dir():
                            points.append(entry)
            proc_mounts = Path("/proc/mounts")
            if proc_mounts.exists():
                try:
                    with proc_mounts.open("r", encoding="utf-8", errors="ignore") as mounts:
                        for line in mounts:
                            parts = line.split()
                            if len(parts) >= 2:
                                mount_path = Path(parts[1])
                                if mount_path.exists() and mount_path.is_dir():
                                    points.append(mount_path)
                except OSError:
                    pass

        unique_points: List[Path] = []
        seen = set()
        for point in points:
            try:
                resolved = point.resolve()
            except OSError:
                resolved = point
            if resolved in seen:
                continue
            seen.add(resolved)
            unique_points.append(resolved)
        return unique_points
