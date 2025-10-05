"""EXT2/EXT3/EXT4 filesystem analyzer."""
from __future__ import annotations

import math
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from ..models import ProgressReport, ResultKind, ResultStatus, ScanMode, ScanResult
from ..utils import ensure_directory, format_bytes, generate_identifier


@dataclass(slots=True)
class ExtGeometry:
    block_size: int
    inode_size: int
    inodes_count: int
    blocks_count: int
    blocks_per_group: int
    inodes_per_group: int
    first_data_block: int
    group_count: int
    descriptor_size: int
    fs_type: str


@dataclass(slots=True)
class ExtGroupDescriptor:
    block_bitmap: int
    inode_bitmap: int
    inode_table: int


@dataclass(slots=True)
class ExtInode:
    inode_index: int
    mode: int
    size: int
    blocks: int
    flags: int
    block_pointers: Tuple[int, ...]
    block_data: bytes

    @property
    def is_directory(self) -> bool:
        return (self.mode & 0xF000) == 0x4000

    @property
    def is_regular_file(self) -> bool:
        return (self.mode & 0xF000) == 0x8000


@dataclass(slots=True)
class ExtEntry:
    record_id: int
    name: str
    path: str
    inode_index: int
    inode: ExtInode


class ExtAnalyzer:
    """Minimal EXT2/3/4 reader able to enumerate and recover files."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.geometry: Optional[ExtGeometry] = None
        self._group_descriptors: List[ExtGroupDescriptor] = []
        self.entries: Dict[int, ExtEntry] = {}

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
        self._group_descriptors = self._read_group_descriptors()
        self.entries.clear()

        results: List[ScanResult] = []
        record_counter = 0

        def visit_directory(inode: ExtInode, parent_path: str) -> None:
            nonlocal record_counter
            for entry_inode, name, file_type in self._iter_directory(inode):
                if len(results) >= limit:
                    return
                if cancel_event and cancel_event.is_set():
                    return
                if name in {".", ".."}:
                    continue
                child_inode = self._read_inode(entry_inode)
                if not child_inode:
                    continue
                full_path = parent_path
                if not full_path.endswith("/"):
                    full_path = f"{full_path}/"
                full_path = f"{full_path}{name}" if full_path != "//" else f"/{name}"
                if parent_path == "":
                    full_path = f"/{name}"

                record_counter += 1
                entry = ExtEntry(
                    record_id=record_counter,
                    name=name,
                    path=full_path,
                    inode_index=entry_inode,
                    inode=child_inode,
                )
                self.entries[record_counter] = entry

                if child_inode.is_directory:
                    visit_directory(child_inode, full_path)
                    continue
                if not child_inode.is_regular_file:
                    continue

                result = ScanResult(
                    identifier=generate_identifier("ext"),
                    display_name=name,
                    location=Path(f"ext://{full_path}"),
                    size_bytes=child_inode.size,
                    modified_at=None,
                    status=ResultStatus.RECOVERABLE,
                    kind=ResultKind.EXISTING,
                    origin=ScanMode.DEEP,
                    metadata={
                        "filesystem": geometry.fs_type,
                        "filesystem_record": str(record_counter),
                        "path": full_path,
                        "size": format_bytes(child_inode.size),
                        "device_path": str(self.path),
                    },
                )
                results.append(result)

                if progress_cb:
                    ratio = min(len(results) / max(limit, 1), 1.0)
                    progress_cb(
                        ProgressReport(
                            message=f"EXT: indexed {len(results)} files",
                            ratio=min(0.6 + ratio * 0.3, 0.9),
                            detail=name,
                        )
                    )

        root_inode = self._read_inode(2)
        if root_inode and root_inode.is_directory:
            visit_directory(root_inode, "")
        return results

    def recover_record(self, record_id: int, destination: Path, *, overwrite: bool = False) -> Path:
        entry = self.entries.get(record_id)
        if not entry:
            raise ValueError(f"EXT record {record_id} not cached")
        inode = entry.inode
        if not inode.is_regular_file:
            raise ValueError("Only regular files can be recovered")
        geometry = self.geometry
        if not geometry:
            raise ValueError("EXT geometry not initialised")
        ensure_directory(destination.parent)
        if destination.exists() and not overwrite:
            raise FileExistsError(f"Destination file already exists: {destination}")

        remaining = inode.size
        with self.path.open("rb", buffering=0) as source, destination.open("wb") as target:
            for block in self._file_blocks(inode):
                if remaining <= 0:
                    break
                data = self._read_block(source, block)
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
    def _read_geometry(self) -> Optional[ExtGeometry]:
        try:
            with self.path.open("rb", buffering=0) as handle:
                handle.seek(1024)
                superblock = handle.read(1024)
        except OSError:
            return None
        if len(superblock) < 1024:
            return None
        magic = struct.unpack_from("<H", superblock, 0x38)[0]
        if magic != 0xEF53:
            return None

        inodes_count = struct.unpack_from("<I", superblock, 0x0)[0]
        blocks_count = struct.unpack_from("<I", superblock, 0x4)[0]
        first_data_block = struct.unpack_from("<I", superblock, 0x14)[0]
        log_block_size = struct.unpack_from("<I", superblock, 0x18)[0]
        block_size = 1024 << log_block_size
        blocks_per_group = struct.unpack_from("<I", superblock, 0x20)[0]
        inodes_per_group = struct.unpack_from("<I", superblock, 0x28)[0]
        rev_level = struct.unpack_from("<I", superblock, 0x4C)[0]
        inode_size = struct.unpack_from("<H", superblock, 0x58)[0] or 128
        feature_incompat = struct.unpack_from("<I", superblock, 0x60)[0]
        feature_ro_compat = struct.unpack_from("<I", superblock, 0x64)[0]
        desc_size = 32
        if rev_level >= 1:
            desc_size = struct.unpack_from("<H", superblock, 0xFE)[0] or 32
            if desc_size < 32:
                desc_size = 32

        fs_type = "ext2"
        if feature_incompat & 0x40:
            fs_type = "ext4"
        elif feature_ro_compat & 0x4:
            fs_type = "ext3"

        if inodes_count == 0 or blocks_count == 0 or blocks_per_group == 0 or inodes_per_group == 0:
            return None

        group_count = math.ceil(blocks_count / blocks_per_group)

        return ExtGeometry(
            block_size=block_size,
            inode_size=inode_size,
            inodes_count=inodes_count,
            blocks_count=blocks_count,
            blocks_per_group=blocks_per_group,
            inodes_per_group=inodes_per_group,
            first_data_block=first_data_block,
            group_count=group_count,
            descriptor_size=desc_size,
            fs_type=fs_type,
        )

    def _read_group_descriptors(self) -> List[ExtGroupDescriptor]:
        geometry = self.geometry
        if not geometry:
            return []
        block_size = geometry.block_size
        desc_size = geometry.descriptor_size
        if block_size == 1024:
            start_block = 2
        else:
            start_block = 1
        start_offset = start_block * block_size
        count = geometry.group_count
        descriptors: List[ExtGroupDescriptor] = []
        try:
            with self.path.open("rb", buffering=0) as handle:
                handle.seek(start_offset)
                data = handle.read(count * desc_size)
        except OSError:
            return []
        for index in range(count):
            base = index * desc_size
            if base + 16 > len(data):
                break
            block_bitmap = struct.unpack_from("<I", data, base + 0)[0]
            inode_bitmap = struct.unpack_from("<I", data, base + 4)[0]
            inode_table = struct.unpack_from("<I", data, base + 8)[0]
            descriptors.append(
                ExtGroupDescriptor(
                    block_bitmap=block_bitmap,
                    inode_bitmap=inode_bitmap,
                    inode_table=inode_table,
                )
            )
        return descriptors

    def _read_inode(self, inode_index: int) -> Optional[ExtInode]:
        geometry = self.geometry
        if not geometry or inode_index <= 0 or inode_index > geometry.inodes_count:
            return None
        group = (inode_index - 1) // geometry.inodes_per_group
        offset_in_group = (inode_index - 1) % geometry.inodes_per_group
        if group >= len(self._group_descriptors):
            return None
        descriptor = self._group_descriptors[group]
        inode_table_block = descriptor.inode_table
        block_size = geometry.block_size
        inode_size = geometry.inode_size
        inode_offset = inode_table_block * block_size + offset_in_group * inode_size
        try:
            with self.path.open("rb", buffering=0) as handle:
                handle.seek(inode_offset)
                raw = handle.read(inode_size)
        except OSError:
            return None
        if len(raw) < 128:
            return None
        mode = struct.unpack_from("<H", raw, 0x0)[0]
        size_lo = struct.unpack_from("<I", raw, 0x4)[0]
        size_high = 0
        flags = struct.unpack_from("<I", raw, 0x20)[0]
        if geometry.fs_type == "ext4" or inode_size >= 160:
            size_high = struct.unpack_from("<I", raw, 0x6C)[0]
        size = (size_high << 32) | size_lo
        blocks = struct.unpack_from("<I", raw, 0x1C)[0]
        block_data = raw[0x28 : 0x28 + 60]
        block_pointers = struct.unpack_from("<15I", block_data)
        return ExtInode(
            inode_index=inode_index,
            mode=mode,
            size=size,
            blocks=blocks,
            flags=flags,
            block_pointers=block_pointers,
            block_data=block_data,
        )

    def _iter_directory(self, inode: ExtInode) -> Iterable[Tuple[int, str, int]]:
        geometry = self.geometry
        if not geometry:
            return []
        entries: List[Tuple[int, str, int]] = []
        for block in self._file_blocks(inode):
            data = self._read_block_bytes(block)
            if not data:
                continue
            offset = 0
            while offset + 8 <= len(data):
                entry_inode = struct.unpack_from("<I", data, offset)[0]
                rec_len = struct.unpack_from("<H", data, offset + 4)[0]
                name_len = data[offset + 6]
                file_type = data[offset + 7]
                if rec_len < 8 or rec_len + offset > len(data):
                    break
                if entry_inode != 0 and name_len > 0:
                    name_bytes = data[offset + 8 : offset + 8 + name_len]
                    try:
                        name = name_bytes.decode("utf-8", errors="ignore")
                    except UnicodeDecodeError:
                        name = name_bytes.decode("latin-1", errors="ignore")
                    entries.append((entry_inode, name, file_type))
                offset += rec_len
        return entries

    def _file_blocks(self, inode: ExtInode) -> List[int]:
        geometry = self.geometry
        if not geometry:
            return []
        if inode.size == 0:
            total_blocks = 0
        else:
            total_blocks = (inode.size + geometry.block_size - 1) // geometry.block_size
        limit = total_blocks if total_blocks else None
        if inode.flags & 0x80000:
            blocks = self._blocks_from_extents(inode, limit)
        else:
            blocks = self._blocks_from_legacy(inode, total_blocks)
        if total_blocks:
            return blocks[: total_blocks]
        return blocks

    def _blocks_from_legacy(self, inode: ExtInode, total_blocks: int) -> List[int]:
        geometry = self.geometry
        if not geometry:
            return []
        remaining = total_blocks or (inode.size // geometry.block_size + 12)
        blocks: List[int] = []
        for pointer in inode.block_pointers[:12]:
            if pointer:
                blocks.append(pointer)
            if total_blocks and len(blocks) >= total_blocks:
                return blocks
        remaining = max(0, (total_blocks or (len(blocks) + 1)) - len(blocks))
        # Single indirect
        if remaining != 0 and inode.block_pointers[12]:
            blocks.extend(
                self._read_indirect_blocks(
                    inode.block_pointers[12],
                    1,
                    total_blocks - len(blocks) if total_blocks else None,
                )
            )
        # Double indirect
        if (not total_blocks or len(blocks) < total_blocks) and inode.block_pointers[13]:
            blocks.extend(
                self._read_indirect_blocks(
                    inode.block_pointers[13],
                    2,
                    total_blocks - len(blocks) if total_blocks else None,
                )
            )
        # Triple indirect
        if (not total_blocks or len(blocks) < total_blocks) and inode.block_pointers[14]:
            blocks.extend(
                self._read_indirect_blocks(
                    inode.block_pointers[14],
                    3,
                    total_blocks - len(blocks) if total_blocks else None,
                )
            )
        return blocks

    def _read_indirect_blocks(self, block: int, depth: int, limit: Optional[int]) -> List[int]:
        if depth <= 0 or block == 0 or limit == 0:
            return []
        entries = self._read_u32_block(block)
        results: List[int] = []
        for entry in entries:
            if entry == 0:
                continue
            if depth == 1:
                results.append(entry)
            else:
                next_limit = None if limit is None else max(limit - len(results), 0)
                results.extend(self._read_indirect_blocks(entry, depth - 1, next_limit))
            if limit is not None and len(results) >= limit:
                break
        return results

    def _read_u32_block(self, block: int) -> List[int]:
        data = self._read_block_bytes(block)
        if not data:
            return []
        count = len(data) // 4
        return [struct.unpack_from("<I", data, i * 4)[0] for i in range(count)]

    def _blocks_from_extents(self, inode: ExtInode, limit: Optional[int]) -> List[int]:
        root = inode.block_data
        blocks_with_logical = self._parse_extent_node(root, limit)
        if not blocks_with_logical:
            return []
        blocks_with_logical.sort(key=lambda item: item[0])
        return [physical for _logical, physical in blocks_with_logical]

    def _parse_extent_node(
        self,
        data: bytes,
        remaining: Optional[int],
        depth_override: Optional[int] = None,
    ) -> List[Tuple[int, int]]:
        if remaining == 0 or len(data) < 12:
            return []
        magic, entries, max_entries, depth, _generation = struct.unpack_from("<HHHHI", data, 0)
        if magic != 0xF30A:
            return []
        if depth_override is not None:
            depth = depth_override
        entries = min(entries, (len(data) - 12) // 12)
        offset = 12
        results: List[Tuple[int, int]] = []
        if depth == 0:
            for _ in range(entries):
                if offset + 12 > len(data):
                    break
                ee_block, ee_len, ee_start_hi, ee_start_lo = struct.unpack_from("<IHHI", data, offset)
                offset += 12
                if ee_len == 0:
                    continue
                block_count = ee_len & 0x7FFF
                start = ((ee_start_hi << 32) | ee_start_lo)
                for idx in range(block_count):
                    logical = ee_block + idx
                    physical = start + idx
                    results.append((logical, physical))
                    if remaining is not None and len(results) >= remaining:
                        return results
        else:
            for _ in range(entries):
                if offset + 12 > len(data):
                    break
                ei_block, ei_leaf_lo, ei_leaf_hi, _ = struct.unpack_from("<IIHH", data, offset)
                offset += 12
                leaf = ((ei_leaf_hi << 32) | ei_leaf_lo)
                child_data = self._read_block_bytes(leaf)
                if not child_data:
                    continue
                next_remaining = None if remaining is None else max(remaining - len(results), 0)
                child_results = self._parse_extent_node(
                    child_data,
                    next_remaining,
                    depth_override=depth - 1,
                )
                results.extend(child_results)
                if remaining is not None and len(results) >= remaining:
                    return results
        return results

    def _read_block_bytes(self, block: int) -> bytes:
        try:
            with self.path.open("rb", buffering=0) as handle:
                return self._read_block(handle, block)
        except OSError:
            return b""

    def _read_block(self, handle, block: int) -> bytes:
        geometry = self.geometry
        if not geometry or block == 0:
            return b""
        block_size = geometry.block_size
        offset = block * block_size
        handle.seek(offset)
        return handle.read(block_size)


__all__ = ["ExtAnalyzer"]
