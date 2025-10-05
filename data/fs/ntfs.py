"""NTFS metadata scanner with basic recovery support."""
from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..models import ProgressReport, ResultKind, ResultStatus, ScanMode, ScanResult
from ..utils import ensure_directory, format_bytes, generate_identifier


@dataclass(slots=True)
class NTFSVolumeGeometry:
    """Geometry information parsed from the NTFS boot sector."""

    bytes_per_sector: int
    sectors_per_cluster: int
    mft_start_lcn: int
    clusters_per_record: int

    @property
    def cluster_size(self) -> int:
        return self.bytes_per_sector * self.sectors_per_cluster

    @property
    def record_size(self) -> int:
        if self.clusters_per_record > 0:
            return self.cluster_size * self.clusters_per_record
        # Negative values indicate a power-of-two size (2**abs(value))
        return 2 ** (-self.clusters_per_record)


@dataclass(slots=True)
class NTFSDataStream:
    """Represents the unnamed $DATA attribute for a record."""

    resident: bool
    resident_data: bytes | None
    runs: List[Tuple[int, int]]  # (byte_offset, length_in_bytes)
    real_size: int


@dataclass(slots=True)
class NTFSEntry:
    record_id: int
    parent_ref: int
    name: str
    is_directory: bool
    data_stream: Optional[NTFSDataStream]
    full_path: Optional[str] = None


class NTFSAnalyzer:
    """NTFS helper able to enumerate records and recover file data."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.geometry: Optional[NTFSVolumeGeometry] = None
        self.entries: Dict[int, NTFSEntry] = {}

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
        geometry = self._read_geometry()
        if not geometry:
            return []
        self.geometry = geometry

        record_size = geometry.record_size or 1024
        mft_offset = geometry.mft_start_lcn * geometry.cluster_size
        raw_entries: Dict[int, NTFSEntry] = {}

        with self.path.open("rb", buffering=0) as handle:
            for index in range(limit):
                if cancel_event and cancel_event.is_set():
                    break
                offset = mft_offset + index * record_size
                handle.seek(offset)
                record = handle.read(record_size)
                if len(record) < 4:
                    break
                if record[0:4] != b"FILE":
                    continue
                flags = struct.unpack_from("<H", record, 0x16)[0]
                if not (flags & 0x01):
                    continue
                attr_offset = struct.unpack_from("<H", record, 0x14)[0]
                if attr_offset == 0 or attr_offset >= record_size:
                    continue
                entry = self._parse_record(index, record, attr_offset, flags, geometry)
                if entry:
                    raw_entries[index] = entry
                    if progress_cb:
                        ratio = min(index / max(limit, 1), 1.0)
                        progress_cb(
                            ProgressReport(
                                message=f"NTFS: indexed {len(raw_entries)} records",
                                ratio=min(0.5 + ratio * 0.3, 0.85),
                                detail=entry.name,
                            )
                        )

        self.entries = raw_entries
        self._build_paths()
        results: List[ScanResult] = []
        for entry in self.entries.values():
            if entry.is_directory or not entry.full_path or not entry.data_stream:
                continue
            metadata = {
                "filesystem": "ntfs",
                "filesystem_record": str(entry.record_id),
                "device_path": str(self.path),
                "path": entry.full_path,
                "size": format_bytes(entry.data_stream.real_size),
            }
            location = Path(f"ntfs://{entry.full_path}")
            result = ScanResult(
                identifier=generate_identifier("ntfs"),
                display_name=entry.name,
                location=location,
                size_bytes=entry.data_stream.real_size,
                modified_at=None,
                status=ResultStatus.RECOVERABLE,
                kind=ResultKind.EXISTING,
                origin=ScanMode.DEEP,
                metadata=metadata,
            )
            results.append(result)
        return results

    def recover_record(self, record_id: int, destination: Path, *, overwrite: bool = False) -> Path:
        entry = self.entries.get(record_id)
        if not entry:
            raise ValueError(f"NTFS record {record_id} not cached")
        if entry.is_directory:
            raise ValueError("Directories cannot be recovered as files")
        if not entry.data_stream:
            raise ValueError("Record has no data stream")
        ensure_directory(destination.parent)
        if destination.exists() and not overwrite:
            raise FileExistsError(f"Destination file already exists: {destination}")

        stream = entry.data_stream
        if stream.resident:
            data = stream.resident_data or b""
            with destination.open("wb") as handle:
                handle.write(data[: stream.real_size])
        else:
            if not self.geometry:
                raise ValueError("Missing NTFS geometry for non-resident recovery")
            remaining = stream.real_size
            with self.path.open("rb", buffering=0) as source, destination.open("wb") as target:
                for offset, length in stream.runs:
                    if remaining <= 0:
                        break
                    read_len = min(length, remaining)
                    source.seek(offset)
                    to_read = read_len
                    chunk_size = max(self.geometry.cluster_size, 1024 * 1024)
                    while to_read > 0:
                        chunk = source.read(min(chunk_size, to_read))
                        if not chunk:
                            break
                        target.write(chunk)
                        to_read -= len(chunk)
                        remaining -= len(chunk)
                    if to_read > 0:
                        raise IOError("Unexpected end while reading NTFS data stream")
        return destination

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _read_geometry(self) -> Optional[NTFSVolumeGeometry]:
        try:
            with self.path.open("rb", buffering=0) as handle:
                boot_sector = handle.read(512)
        except OSError:
            return None
        if len(boot_sector) < 512 or boot_sector[3:11] != b"NTFS    ":
            return None
        bytes_per_sector = struct.unpack_from("<H", boot_sector, 11)[0] or 512
        sectors_per_cluster = boot_sector[13] or 8
        mft_start_lcn = struct.unpack_from("<Q", boot_sector, 48)[0]
        clusters_per_record_raw = struct.unpack_from("<b", boot_sector, 64)[0] or -3
        return NTFSVolumeGeometry(
            bytes_per_sector=bytes_per_sector,
            sectors_per_cluster=sectors_per_cluster,
            mft_start_lcn=mft_start_lcn,
            clusters_per_record=clusters_per_record_raw,
        )

    def _parse_record(
        self,
        record_id: int,
        record: bytes,
        attr_offset: int,
        flags: int,
        geometry: NTFSVolumeGeometry,
    ) -> Optional[NTFSEntry]:
        record_size = len(record)
        offset = attr_offset
        best_name: Optional[str] = None
        best_namespace = 0xFF
        parent_ref = 0
        data_stream: Optional[NTFSDataStream] = None

        while offset + 8 < record_size:
            attr_type = struct.unpack_from("<I", record, offset)[0]
            if attr_type == 0xFFFFFFFF:
                break
            attr_length = struct.unpack_from("<I", record, offset + 4)[0]
            if attr_length <= 0:
                break
            non_resident = record[offset + 8]
            name_length = record[offset + 9]
            name_offset = struct.unpack_from("<H", record, offset + 10)[0]
            content_offset = None
            content_length = None
            runlist_offset = None
            real_size = None
            if non_resident == 0:
                content_length = struct.unpack_from("<I", record, offset + 16)[0]
                content_offset = struct.unpack_from("<H", record, offset + 20)[0]
            else:
                runlist_offset = struct.unpack_from("<H", record, offset + 32)[0]
                real_size = struct.unpack_from("<Q", record, offset + 48)[0]

            if attr_type == 0x30 and non_resident == 0 and content_offset is not None:
                start = offset + content_offset
                end = start + content_length if content_length else record_size
                content = record[start:end]
                if len(content) >= 0x42:
                    parent_ref_raw = struct.unpack_from("<Q", content, 0)[0]
                    parent_ref = parent_ref_raw & 0x0000FFFFFFFFFFFF
                    name_len = content[64]
                    namespace = content[65]
                    name_bytes = content[66 : 66 + name_len * 2]
                    try:
                        name = name_bytes.decode("utf-16le", errors="ignore")
                    except UnicodeDecodeError:
                        name = ""
                    if name and namespace <= best_namespace:
                        best_namespace = namespace
                        best_name = name
                    if non_resident == 0 and content_length >= 56:
                        real_size = struct.unpack_from("<Q", content, 48)[0]
                    if real_size is not None and data_stream is None:
                        data_stream = data_stream or NTFSDataStream(True, b"", [], real_size)

            if attr_type == 0x80 and name_length == 0:
                if non_resident == 0 and content_offset is not None and content_length is not None:
                    data = record[offset + content_offset : offset + content_offset + content_length]
                    data_stream = NTFSDataStream(True, data, [], content_length)
                elif non_resident == 1 and runlist_offset is not None:
                    run_data = record[offset + runlist_offset : offset + attr_length]
                    runs = self._parse_runlist(run_data, geometry.cluster_size)
                    data_stream = NTFSDataStream(False, None, runs, real_size or 0)
            offset += attr_length

        if not best_name:
            return None
        if data_stream and not data_stream.resident and data_stream.real_size == 0:
            # Some metadata records (directories) expose empty data streams
            data_stream = None
        is_directory = bool(flags & 0x02)
        return NTFSEntry(
            record_id=record_id,
            parent_ref=parent_ref,
            name=best_name,
            is_directory=is_directory,
            data_stream=data_stream,
        )

    def _parse_runlist(self, run_data: bytes, cluster_size: int) -> List[Tuple[int, int]]:
        runs: List[Tuple[int, int]] = []
        index = 0
        current_lcn = 0
        while index < len(run_data):
            header = run_data[index]
            index += 1
            if header == 0:
                break
            length_size = header & 0x0F
            offset_size = header >> 4
            run_length = int.from_bytes(run_data[index : index + length_size], "little")
            index += length_size
            offset_bytes = run_data[index : index + offset_size]
            index += offset_size
            if offset_size > 0:
                offset_padded = offset_bytes + (b"\x00" * (8 - offset_size))
                offset_value = int.from_bytes(offset_padded, "little", signed=True)
                current_lcn += offset_value
            start_byte = current_lcn * cluster_size
            runs.append((start_byte, run_length * cluster_size))
        return runs

    def _build_paths(self) -> None:
        cache: Dict[int, str] = {}

        def resolve(record_id: int, depth: int = 0) -> Optional[str]:
            if record_id in cache:
                return cache[record_id]
            if depth > 64:
                return None
            entry = self.entries.get(record_id)
            if not entry:
                return None
            if record_id == 5:
                cache[record_id] = "/"
                entry.full_path = "/"
                return "/"
            parent = resolve(entry.parent_ref, depth + 1)
            if not parent or parent == "/":
                path = f"/{entry.name}"
            else:
                path = f"{parent}/{entry.name}"
            cache[record_id] = path
            entry.full_path = path
            return path

        for record_id in list(self.entries.keys()):
            resolve(record_id)

__all__ = ["NTFSAnalyzer", "NTFSVolumeGeometry"]
