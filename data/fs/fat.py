"""FAT/FAT32 metadata scanner with basic recovery support."""
from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from ..models import ProgressReport, ResultKind, ResultStatus, ScanMode, ScanResult
from ..utils import ensure_directory, format_bytes, generate_identifier


@dataclass(slots=True)
class FATGeometry:
    """Describes core layout parameters for a FAT volume."""

    bytes_per_sector: int
    sectors_per_cluster: int
    reserved_sectors: int
    num_fats: int
    sectors_per_fat: int
    root_dir_entries: int
    total_sectors: int
    fat_type: str
    root_dir_sectors: int
    first_data_sector: int
    root_dir_cluster: int


@dataclass(slots=True)
class FATEntry:
    """Cached directory entry used for recovery."""

    record_id: int
    name: str
    path: str
    is_directory: bool
    start_cluster: int
    size: int


class FATAnalyzer:
    """FAT/FAT32 helper able to enumerate directory entries and recover data."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.geometry: Optional[FATGeometry] = None
        self._fat_table: List[int] = []
        self.entries: Dict[int, FATEntry] = {}

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
        if geometry.fat_type == "fat12":
            return []
        self.geometry = geometry
        self._fat_table = self._read_fat_table()
        self.entries.clear()

        results: List[ScanResult] = []
        record_counter = 0

        def visit_directory(start_cluster: int, parent_path: str, is_root: bool = False) -> None:
            nonlocal record_counter
            directory_data = self._read_directory_bytes(start_cluster, is_root=is_root)
            for entry_bytes in self._iter_directory_entries(directory_data):
                if len(results) >= limit:
                    return
                if cancel_event and cancel_event.is_set():
                    return
                name, is_dir = entry_bytes[0]
                start_cluster_entry = entry_bytes[1]
                size = entry_bytes[2]
                full_path = parent_path
                if parent_path.endswith("/"):
                    full_path = f"{parent_path}{name}"
                else:
                    full_path = f"{parent_path}/{name}"

                record_counter += 1
                entry = FATEntry(
                    record_id=record_counter,
                    name=name,
                    path=full_path,
                    is_directory=is_dir,
                    start_cluster=start_cluster_entry,
                    size=size,
                )
                self.entries[record_counter] = entry

                if is_dir:
                    visit_directory(start_cluster_entry, full_path, is_root=False)
                    if len(results) >= limit:
                        return
                    continue

                result = ScanResult(
                    identifier=generate_identifier("fat"),
                    display_name=name,
                    location=Path(f"fat://{full_path}"),
                    size_bytes=size,
                    modified_at=None,
                    status=ResultStatus.RECOVERABLE,
                    kind=ResultKind.EXISTING,
                    origin=ScanMode.DEEP,
                    metadata={
                        "filesystem": geometry.fat_type,
                        "filesystem_record": str(record_counter),
                        "path": full_path,
                        "size": format_bytes(size),
                        "device_path": str(self.path),
                    },
                )
                results.append(result)

                if progress_cb:
                    ratio = min(len(results) / max(limit, 1), 1.0)
                    progress_cb(
                        ProgressReport(
                            message=f"FAT: indexed {len(results)} files",
                            ratio=min(0.6 + ratio * 0.3, 0.9),
                            detail=name,
                        )
                    )
                if len(results) >= limit:
                    return

        visit_directory(geometry.root_dir_cluster, parent_path="", is_root=True)
        return results

    def recover_record(self, record_id: int, destination: Path, *, overwrite: bool = False) -> Path:
        entry = self.entries.get(record_id)
        if not entry:
            raise ValueError(f"FAT record {record_id} not cached")
        if entry.is_directory:
            raise ValueError("Directories cannot be recovered as files")
        geometry = self.geometry
        if not geometry:
            raise ValueError("FAT geometry not initialised")
        ensure_directory(destination.parent)
        if destination.exists() and not overwrite:
            raise FileExistsError(f"Destination file already exists: {destination}")

        remaining = entry.size
        with self.path.open("rb", buffering=0) as handle, destination.open("wb") as target:
            if entry.start_cluster < 2 or remaining == 0:
                return destination
            for cluster in self._cluster_chain(entry.start_cluster):
                if remaining <= 0:
                    break
                data = self._read_cluster(handle, cluster)
                if not data:
                    break
                if remaining < len(data):
                    target.write(data[:remaining])
                else:
                    target.write(data)
                remaining -= len(data)
        return destination

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _read_geometry(self) -> Optional[FATGeometry]:
        try:
            with self.path.open("rb", buffering=0) as handle:
                boot_sector = handle.read(512)
        except OSError:
            return None
        if len(boot_sector) < 62:
            return None

        bytes_per_sector = struct.unpack_from("<H", boot_sector, 11)[0] or 512
        sectors_per_cluster = boot_sector[13] or 1
        reserved_sectors = struct.unpack_from("<H", boot_sector, 14)[0] or 1
        num_fats = boot_sector[16] or 2
        root_dir_entries = struct.unpack_from("<H", boot_sector, 17)[0]
        total_sectors_16 = struct.unpack_from("<H", boot_sector, 19)[0]
        total_sectors_32 = struct.unpack_from("<I", boot_sector, 32)[0]
        total_sectors = total_sectors_16 or total_sectors_32
        if total_sectors == 0:
            return None

        sectors_per_fat_16 = struct.unpack_from("<H", boot_sector, 22)[0]
        sectors_per_fat_32 = struct.unpack_from("<I", boot_sector, 36)[0]
        sectors_per_fat = sectors_per_fat_16 or sectors_per_fat_32
        if sectors_per_fat == 0:
            return None

        root_dir_sectors = ((root_dir_entries * 32) + (bytes_per_sector - 1)) // bytes_per_sector
        first_data_sector = reserved_sectors + (num_fats * sectors_per_fat) + root_dir_sectors
        data_sectors = total_sectors - first_data_sector
        if data_sectors <= 0:
            return None
        cluster_count = data_sectors // sectors_per_cluster
        if cluster_count < 4085:
            fat_type = "fat12"
        elif cluster_count < 65525:
            fat_type = "fat16"
        else:
            fat_type = "fat32"

        if fat_type == "fat32":
            root_dir_cluster = struct.unpack_from("<I", boot_sector, 44)[0]
            if root_dir_cluster < 2:
                root_dir_cluster = 2
            root_dir_sectors = 0
            first_data_sector = reserved_sectors + (num_fats * sectors_per_fat)
        else:
            root_dir_cluster = 0

        return FATGeometry(
            bytes_per_sector=bytes_per_sector,
            sectors_per_cluster=sectors_per_cluster,
            reserved_sectors=reserved_sectors,
            num_fats=num_fats,
            sectors_per_fat=sectors_per_fat,
            root_dir_entries=root_dir_entries,
            total_sectors=total_sectors,
            fat_type=fat_type,
            root_dir_sectors=root_dir_sectors,
            first_data_sector=first_data_sector,
            root_dir_cluster=root_dir_cluster,
        )

    def _read_fat_table(self) -> List[int]:
        geometry = self.geometry
        if not geometry:
            return []
        fat_offset = geometry.reserved_sectors * geometry.bytes_per_sector
        fat_length = geometry.sectors_per_fat * geometry.bytes_per_sector
        try:
            with self.path.open("rb", buffering=0) as handle:
                handle.seek(fat_offset)
                table_data = handle.read(fat_length)
        except OSError:
            return []

        entries: List[int] = []
        if geometry.fat_type == "fat32":
            count = len(table_data) // 4
            for idx in range(count):
                value = struct.unpack_from("<I", table_data, idx * 4)[0] & 0x0FFFFFFF
                entries.append(value)
        else:
            count = len(table_data) // 2
            for idx in range(count):
                value = struct.unpack_from("<H", table_data, idx * 2)[0]
                entries.append(value)
        return entries

    def _cluster_chain(self, start_cluster: int) -> Iterable[int]:
        geometry = self.geometry
        table = self._fat_table
        if not geometry or not table or start_cluster < 2:
            return []

        chain: List[int] = []
        current = start_cluster
        visited: set[int] = set()
        while 2 <= current < len(table):
            if current in visited:
                break
            visited.add(current)
            chain.append(current)
            value = table[current]
            if geometry.fat_type == "fat32":
                if value >= 0x0FFFFFF8:
                    break
            else:
                if value >= 0xFFF8:
                    break
            if value == 0:
                break
            current = value
        return chain

    def _read_cluster(self, handle, cluster: int) -> bytes:
        geometry = self.geometry
        if not geometry or cluster < 2:
            return b""
        sector = geometry.first_data_sector + (cluster - 2) * geometry.sectors_per_cluster
        offset = sector * geometry.bytes_per_sector
        length = geometry.sectors_per_cluster * geometry.bytes_per_sector
        handle.seek(offset)
        return handle.read(length)

    def _read_directory_bytes(self, start_cluster: int, *, is_root: bool) -> bytes:
        geometry = self.geometry
        if not geometry:
            return b""

        if is_root and geometry.fat_type != "fat32":
            start_sector = geometry.reserved_sectors + (geometry.num_fats * geometry.sectors_per_fat)
            offset = start_sector * geometry.bytes_per_sector
            length = geometry.root_dir_sectors * geometry.bytes_per_sector
            with self.path.open("rb", buffering=0) as handle:
                handle.seek(offset)
                return handle.read(length)

        data = bytearray()
        if start_cluster >= 2:
            with self.path.open("rb", buffering=0) as handle:
                for cluster in self._cluster_chain(start_cluster):
                    data.extend(self._read_cluster(handle, cluster))
        return bytes(data)

    def _iter_directory_entries(self, directory: bytes) -> Iterable[tuple[tuple[str, bool], int, int]]:
        geometry = self.geometry
        if not geometry:
            return []
        entries: List[tuple[tuple[str, bool], int, int]] = []
        for index in range(0, len(directory), 32):
            entry = directory[index : index + 32]
            if len(entry) < 32:
                continue
            first_byte = entry[0]
            if first_byte == 0x00:
                break
            if first_byte == 0xE5:
                continue
            attrs = entry[11]
            if attrs == 0x0F:
                continue
            if attrs & 0x08:
                continue
            name_raw = entry[0:11]
            name = name_raw[0:8].decode("ascii", errors="ignore").rstrip()
            ext = name_raw[8:11].decode("ascii", errors="ignore").rstrip()
            if not name:
                continue
            if ext:
                filename = f"{name}.{ext}"
            else:
                filename = name
            is_dir = bool(attrs & 0x10)
            if filename == "":
                continue
            if is_dir and filename in {".", ".."}:
                continue
            cluster_low = struct.unpack_from("<H", entry, 26)[0]
            cluster_high = 0
            if geometry.fat_type == "fat32":
                cluster_high = struct.unpack_from("<H", entry, 20)[0]
            start_cluster = (cluster_high << 16) | cluster_low
            size = struct.unpack_from("<I", entry, 28)[0]
            entries.append(((filename, is_dir), start_cluster, size))
        return entries


__all__ = ["FATAnalyzer"]
