"""Apple filesystem analyzers (HFS+ and APFS)."""
from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from ..models import ProgressReport, ResultKind, ResultStatus, ScanMode, ScanResult
from ..utils import ensure_directory, format_bytes, generate_identifier

try:  # Optional dependency for APFS containers
    import pyfsapfs  # type: ignore
except ImportError:  # pragma: no cover - dependency optional
    pyfsapfs = None  # type: ignore

try:  # Optional dependency for HFS+ volumes
    import pytsk3  # type: ignore
except ImportError:  # pragma: no cover - dependency optional
    pytsk3 = None  # type: ignore


@dataclass(slots=True)
class _RecoveredEntry:
    record_id: int
    name: str
    full_path: str
    size: int
    origin: str  # "apfs", "hfs", or "simple"
    aux: Tuple


class AppleFSAnalyzer:
    """Best-effort analyzer for Apple file systems (APFS, HFS+, fallback)."""

    SIMPLE_SIGNATURE = b"AFS0"

    def __init__(self, path: Path) -> None:
        self.path = path
        self._entries: Dict[int, _RecoveredEntry] = {}
        self._simple_header: Optional[tuple[int, int, int, int]] = None
        self._active_mode: Optional[str] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def scan(
        self,
        *,
        limit: int = 4_096,
        cancel_event=None,
        progress_cb=None,
    ) -> List[ScanResult]:
        self._entries.clear()

        scanners: Iterable[str] = ("apfs", "hfs", "simple")
        for mode in scanners:
            if cancel_event and cancel_event.is_set():
                break
            if mode == "apfs":
                results = self._scan_apfs(limit=limit, cancel_event=cancel_event, progress_cb=progress_cb)
            elif mode == "hfs":
                results = self._scan_hfs(limit=limit, cancel_event=cancel_event, progress_cb=progress_cb)
            else:
                results = self._scan_simple(limit=limit, cancel_event=cancel_event, progress_cb=progress_cb)
            if results:
                self._active_mode = mode if mode != "simple" else "hfs"
                return results
        self._active_mode = None
        return []

    def recover_record(self, record_id: int, destination: Path, *, overwrite: bool = False) -> Path:
        entry = self._entries.get(record_id)
        if not entry:
            raise ValueError(f"AppleFS record {record_id} not cached")

        ensure_directory(destination.parent)
        if destination.exists() and not overwrite:
            raise FileExistsError(f"Destination file already exists: {destination}")

        if entry.origin == "apfs":
            return self._recover_apfs(entry, destination)
        if entry.origin == "hfs":
            return self._recover_hfs(entry, destination)
        return self._recover_simple(entry, destination)

    # ------------------------------------------------------------------
    # APFS handling (pyfsapfs)
    # ------------------------------------------------------------------
    def _scan_apfs(self, *, limit: int, cancel_event, progress_cb) -> List[ScanResult]:
        if pyfsapfs is None:
            return []
        offsets: List[int] = self._discover_offsets(apfs=True)
        results: List[ScanResult] = []
        for offset in offsets:
            if cancel_event and cancel_event.is_set():
                break
            partial = self._scan_apfs_at_offset(offset, limit=limit, cancel_event=cancel_event, progress_cb=progress_cb)
            if partial:
                results = partial
                break
        if results:
            self._active_mode = "apfs"
        return results

    def _scan_apfs_at_offset(self, offset: int, *, limit: int, cancel_event, progress_cb) -> List[ScanResult]:
        if pyfsapfs is None:
            return []
        container = pyfsapfs.container()
        try:
            if offset:
                container.open(str(self.path), offset=offset)
            else:
                container.open(str(self.path))
        except OSError:
            return []
        results: List[ScanResult] = []
        record_counter = 0

        def emit(file_entry, full_path: str, volume_index: int) -> None:
            nonlocal record_counter, results
            identifier = file_entry.get_identifier()
            size = file_entry.get_size() or 0
            record_counter += 1
            record = _RecoveredEntry(
                record_id=record_counter,
                name=file_entry.get_name() or "",
                full_path=full_path,
                size=size,
                origin="apfs",
                aux=(volume_index, identifier),
            )
            self._entries[record_counter] = record
            result = ScanResult(
                identifier=generate_identifier("apfs"),
                display_name=record.name,
                location=Path(f"apfs://volume{volume_index}{full_path}"),
                size_bytes=size,
                modified_at=None,
                status=ResultStatus.RECOVERABLE,
                kind=ResultKind.EXISTING,
                origin=ScanMode.DEEP,
                metadata={
                    "filesystem": "apfs",
                    "filesystem_record": str(record_counter),
                    "path": full_path,
                    "size": format_bytes(size),
                },
            )
            results.append(result)
            if progress_cb:
                ratio = min(len(results) / max(limit, 1), 1.0)
                progress_cb(
                    ProgressReport(
                        message=f"APFS: indexed {len(results)} files",
                        ratio=min(0.6 + ratio * 0.3, 0.9),
                        detail=record.name,
                    )
                )

        try:
            volume_count = container.get_number_of_volumes() or 0
        except AttributeError:
            volume_count = 0

        for volume_index in range(volume_count):
            if cancel_event and cancel_event.is_set():
                break
            volume = container.get_volume(volume_index)
            root = volume.get_root_directory()
            if not root:
                continue
            self._walk_apfs(volume, root, "", volume_index, emit, limit, cancel_event)
            if results:
                break

        container.close()
        return results

    def _walk_apfs(
        self,
        volume,
        entry,
        parent_path: str,
        volume_index: int,
        emit,
        limit: int,
        cancel_event,
    ) -> None:
        if cancel_event and cancel_event.is_set():
            return
        name = entry.get_name() or ""
        is_root = parent_path == ""
        full_path = parent_path if is_root else f"{parent_path}/{name}" if parent_path else f"/{name}"
        file_mode = entry.get_file_mode() or 0
        file_type = file_mode & 0o170000
        regular_file = file_type == 0o100000
        directory = file_type == 0o040000

        if regular_file:
            emit(entry, full_path or "/" + name, volume_index)
            if limit and len(self._entries) >= limit:
                return

        if directory or is_root:
            try:
                total = entry.get_number_of_sub_file_entries() or 0
            except AttributeError:
                total = 0
            for index in range(total):
                if cancel_event and cancel_event.is_set():
                    break
                child = entry.get_sub_file_entry(index)
                if not child:
                    continue
                child_name = child.get_name() or ""
                if child_name in {".", ".."}:
                    continue
                child_path = full_path if full_path else ""
                self._walk_apfs(volume, child, child_path, volume_index, emit, limit, cancel_event)
                if limit and len(self._entries) >= limit:
                    return

    def _recover_apfs(self, entry: _RecoveredEntry, destination: Path) -> Path:
        if pyfsapfs is None:
            raise RuntimeError("pyfsapfs not available")
        volume_index, identifier = entry.aux
        container = pyfsapfs.container()
        container.open(str(self.path))
        try:
            volume = container.get_volume(volume_index)
            file_entry = volume.get_file_entry_by_identifier(identifier)
            if not file_entry:
                raise ValueError("APFS file entry not found")
            remaining = entry.size
            offset = 0
            chunk_size = 1024 * 1024
            with destination.open("wb") as target:
                while remaining > 0:
                    buffer = file_entry.read_buffer_at_offset(min(chunk_size, remaining), offset)
                    if not buffer:
                        break
                    target.write(buffer)
                    read_len = len(buffer)
                    remaining -= read_len
                    offset += read_len
        finally:
            container.close()
        return destination

    # ------------------------------------------------------------------
    # HFS+ handling (pytsk3)
    # ------------------------------------------------------------------
    def _scan_hfs(self, *, limit: int, cancel_event, progress_cb) -> List[ScanResult]:
        if pytsk3 is None:
            return []
        offsets = self._discover_offsets(apfs=False)
        results: List[ScanResult] = []
        record_counter = 0

        def emit(full_path: str, size: int) -> None:
            nonlocal record_counter, results
            record_counter += 1
            name = full_path.rsplit("/", 1)[-1] if full_path != "/" else "/"
            record = _RecoveredEntry(
                record_id=record_counter,
                name=name,
                full_path=full_path,
                size=size,
                origin="hfs",
                aux=(full_path,),
            )
            self._entries[record_counter] = record
            result = ScanResult(
                identifier=generate_identifier("hfs"),
                display_name=name,
                location=Path(f"hfs://{full_path}"),
                size_bytes=size,
                modified_at=None,
                status=ResultStatus.RECOVERABLE,
                kind=ResultKind.EXISTING,
                origin=ScanMode.DEEP,
                metadata={
                    "filesystem": "hfs",
                    "filesystem_record": str(record_counter),
                    "path": full_path,
                    "size": format_bytes(size),
                },
            )
            results.append(result)
            if progress_cb:
                ratio = min(len(results) / max(limit, 1), 1.0)
                progress_cb(
                    ProgressReport(
                        message=f"HFS+: indexed {len(results)} files",
                        ratio=min(0.6 + ratio * 0.3, 0.9),
                        detail=name,
                    )
                )

        def walk(directory, current_path: str) -> None:
            if cancel_event and cancel_event.is_set():
                return
            for entry in directory:
                name_bytes = entry.info.name.name
                if not name_bytes:
                    continue
                name = name_bytes.decode("utf-8", errors="ignore")
                if name in {".", ".."}:
                    continue
                meta = entry.info.meta
                if meta is None:
                    continue
                meta_type = int(meta.type)
                full_path = f"{current_path}/{name}" if current_path else f"/{name}"
                if meta_type == pytsk3.TSK_FS_META_TYPE_DIR:
                    try:
                        subdir = entry.as_directory()
                    except (IOError, OSError, pytsk3.TSKError):
                        continue
                    walk(subdir, full_path)
                elif meta_type == pytsk3.TSK_FS_META_TYPE_REG:
                    size = int(meta.size or 0)
                    emit(full_path, size)
                    if limit and len(self._entries) >= limit:
                        return

        for offset in offsets:
            if cancel_event and cancel_event.is_set():
                break
            try:
                img = pytsk3.Img_Info(str(self.path)) if offset == 0 else pytsk3.Img_Info(str(self.path), offset=offset)
                fs = pytsk3.FS_Info(img)
            except Exception:
                continue
            self._entries.clear()
            results.clear()
            record_counter = 0
            root_dir = fs.open_dir(path="/")
            walk(root_dir, "")
            if results:
                self._active_mode = "hfs"
                break
        return results

    def _recover_hfs(self, entry: _RecoveredEntry, destination: Path) -> Path:
        if pytsk3 is None:
            raise RuntimeError("pytsk3 not available")
        img = pytsk3.Img_Info(str(self.path))
        fs = pytsk3.FS_Info(img)
        file_object = fs.open(entry.aux[0])
        remaining = entry.size
        offset = 0
        chunk = 1024 * 1024
        with destination.open("wb") as target:
            while remaining > 0:
                data = file_object.read_random(offset, min(chunk, remaining))
                if not data:
                    break
                target.write(data)
                remaining -= len(data)
                offset += len(data)
        return destination

    # ------------------------------------------------------------------
    # Simplified fallback (legacy test fixtures)
    # ------------------------------------------------------------------
    def _scan_simple(self, *, limit: int, cancel_event, progress_cb) -> List[ScanResult]:
        try:
            with self.path.open("rb") as handle:
                header = handle.read(20)
        except OSError:
            return []
        if len(header) < 20 or not header.startswith(self.SIMPLE_SIGNATURE):
            return []

        _, block_size, total_blocks, catalog_start, catalog_blocks = struct.unpack(
            ">4sIIII", header
        )
        self._simple_header = (block_size, total_blocks, catalog_start, catalog_blocks)
        catalog_bytes = self._read_simple_blocks(catalog_start, catalog_blocks)
        if not catalog_bytes:
            return []

        count = struct.unpack_from(">I", catalog_bytes, 0)[0]
        offset = 4
        record_counter = 0
        results: List[ScanResult] = []

        for _ in range(count):
            if offset + 10 > len(catalog_bytes):
                break
            entry_type = struct.unpack_from(">H", catalog_bytes, offset)[0]
            offset += 2
            name_len = struct.unpack_from(">H", catalog_bytes, offset)[0]
            offset += 2
            name_bytes = catalog_bytes[offset : offset + name_len]
            offset += name_len
            name = name_bytes.decode("utf-8", errors="ignore")
            size = struct.unpack_from(">Q", catalog_bytes, offset)[0]
            offset += 8
            start_block = struct.unpack_from(">I", catalog_bytes, offset)[0]
            offset += 4
            block_count = struct.unpack_from(">I", catalog_bytes, offset)[0]
            offset += 4
            if entry_type != 1:
                continue
            record_counter += 1
            full_path = f"/{name}"
            record = _RecoveredEntry(
                record_id=record_counter,
                name=name,
                full_path=full_path,
                size=size,
                origin="simple",
                aux=(start_block, block_count),
            )
            self._entries[record_counter] = record
            result = ScanResult(
                identifier=generate_identifier("hfs"),
                display_name=name,
                location=Path(f"hfs://{name}"),
                size_bytes=size,
                modified_at=None,
                status=ResultStatus.RECOVERABLE,
                kind=ResultKind.EXISTING,
                origin=ScanMode.DEEP,
                metadata={
                    "filesystem": "hfs",
                    "filesystem_record": str(record_counter),
                    "path": full_path,
                    "size": format_bytes(size),
                },
            )
            results.append(result)
            if progress_cb:
                ratio = min(len(results) / max(limit, 1), 1.0)
                progress_cb(
                    ProgressReport(
                        message=f"HFS(simple): indexed {len(results)} files",
                        ratio=min(0.6 + ratio * 0.3, 0.9),
                        detail=name,
                    )
                )
            if limit and len(results) >= limit:
                break

        return results

    def _recover_simple(self, entry: _RecoveredEntry, destination: Path) -> Path:
        if not self._simple_header:
            raise ValueError("Missing simple header")
        block_size, _, _, _ = self._simple_header
        start_block, block_count = entry.aux
        start = start_block * block_size
        length = block_count * block_size
        remaining = entry.size
        try:
            with self.path.open("rb") as handle, destination.open("wb") as target:
                handle.seek(start)
                while remaining > 0 and length > 0:
                    chunk = handle.read(min(1024 * 1024, remaining, length))
                    if not chunk:
                        break
                    target.write(chunk)
                    remaining -= len(chunk)
                    length -= len(chunk)
        except OSError as exc:
            raise IOError(f"Failed to recover simple HFS entry: {exc}") from exc
        return destination

    def _read_simple_blocks(self, start_block: int, count: int) -> bytes:
        if not self._simple_header:
            return b""
        block_size, _, _, _ = self._simple_header
        start = start_block * block_size
        length = count * block_size
        try:
            with self.path.open("rb") as handle:
                handle.seek(start)
                return handle.read(length)
        except OSError:
            return b""

    @property
    def filesystem_name(self) -> Optional[str]:
        return self._active_mode

    # ------------------------------------------------------------------
    # Partition discovery helpers
    # ------------------------------------------------------------------
    def _discover_offsets(self, *, apfs: bool) -> List[int]:
        offsets = [0]
        if pytsk3 is None:
            return offsets
        try:
            img = pytsk3.Img_Info(str(self.path))
            volume = pytsk3.Volume_Info(img)
        except Exception:
            return offsets

        for part in volume:
            desc = (part.desc or b"").decode("utf-8", errors="ignore").lower()
            has_flag = bool(part.flags & pytsk3.TSK_VS_PART_FLAG_ALLOC)
            if not has_flag:
                continue
            start_offset = int(part.start * volume.info.block_size)
            if apfs:
                if "apfs" in desc or "container" in desc:
                    offsets.append(start_offset)
            else:
                if "hfs" in desc or "mac" in desc:
                    offsets.append(start_offset)
        return offsets


__all__ = ["AppleFSAnalyzer"]
