from __future__ import annotations

import struct
from pathlib import Path


def build_fat16_image(path: Path, *, content: bytes = b"Hello FAT") -> None:
    """Create a minimal FAT16 disk image containing a single file."""

    bytes_per_sector = 512
    sectors_per_cluster = 1
    reserved_sectors = 1
    num_fats = 1
    root_entries = 16
    sectors_per_fat = 16
    first_data_sector = reserved_sectors + num_fats * sectors_per_fat + ((root_entries * 32) + (bytes_per_sector - 1)) // bytes_per_sector
    data_sectors = 4096
    total_sectors = first_data_sector + data_sectors

    image = bytearray(bytes_per_sector * total_sectors)

    # Boot sector header
    image[0:3] = b"\xEB\x3C\x90"
    image[3:11] = b"FAKEFAT "
    struct.pack_into("<H", image, 11, bytes_per_sector)
    image[13] = sectors_per_cluster
    struct.pack_into("<H", image, 14, reserved_sectors)
    image[16] = num_fats
    struct.pack_into("<H", image, 17, root_entries)
    struct.pack_into("<H", image, 19, total_sectors)
    image[21] = 0xF8
    struct.pack_into("<H", image, 22, sectors_per_fat)
    struct.pack_into("<I", image, 28, 0)
    image[510] = 0x55
    image[511] = 0xAA

    # FAT table (sector 1)
    fat_offset = bytes_per_sector * reserved_sectors
    struct.pack_into("<H", image, fat_offset + 0, 0xFFF8)
    struct.pack_into("<H", image, fat_offset + 2, 0xFFFF)
    struct.pack_into("<H", image, fat_offset + 4, 0xFFFF)

    # Root directory
    root_dir_sector = reserved_sectors + num_fats * sectors_per_fat
    root_dir_offset = root_dir_sector * bytes_per_sector
    name_field = b"HELLO   TXT"
    image[root_dir_offset : root_dir_offset + 11] = name_field
    image[root_dir_offset + 11] = 0x20
    struct.pack_into("<H", image, root_dir_offset + 26, 2)
    struct.pack_into("<I", image, root_dir_offset + 28, len(content))

    image[root_dir_offset + 32] = 0x00

    data_sector = first_data_sector
    data_offset = data_sector * bytes_per_sector
    image[data_offset : data_offset + len(content)] = content

    path.write_bytes(bytes(image))


def build_ext2_image(path: Path, *, content: bytes = b"Hello EXT") -> None:
    """Create a minimal EXT2 disk image containing a single regular file."""

    block_size = 1024
    total_blocks = 128
    inodes_count = 32
    blocks_per_group = 128
    inodes_per_group = 32
    inode_size = 128

    image = bytearray(block_size * total_blocks)

    # Superblock (block 1, offset 1024)
    super_offset = 1024
    struct.pack_into("<I", image, super_offset + 0x0, inodes_count)
    struct.pack_into("<I", image, super_offset + 0x4, total_blocks)
    struct.pack_into("<I", image, super_offset + 0x8, 0)
    used_blocks = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
    struct.pack_into("<I", image, super_offset + 0xC, total_blocks - len(used_blocks))
    reserved_inodes = set(range(1, 11))
    used_inodes = reserved_inodes | {12}
    struct.pack_into("<I", image, super_offset + 0x10, inodes_count - len(used_inodes))
    struct.pack_into("<I", image, super_offset + 0x14, 1)
    struct.pack_into("<I", image, super_offset + 0x18, 0)  # log block size
    struct.pack_into("<I", image, super_offset + 0x1C, 0)
    struct.pack_into("<I", image, super_offset + 0x20, blocks_per_group)
    struct.pack_into("<I", image, super_offset + 0x24, blocks_per_group)
    struct.pack_into("<I", image, super_offset + 0x28, inodes_per_group)
    struct.pack_into("<H", image, super_offset + 0x38, 0xEF53)
    struct.pack_into("<I", image, super_offset + 0x4C, 1)
    struct.pack_into("<I", image, super_offset + 0x54, 11)
    struct.pack_into("<H", image, super_offset + 0x58, inode_size)
    struct.pack_into("<I", image, super_offset + 0x60, 0)
    struct.pack_into("<I", image, super_offset + 0x64, 0)
    struct.pack_into("<H", image, super_offset + 0xFE, 32)

    # Group descriptor (block 2)
    gd_offset = 2 * block_size
    struct.pack_into("<I", image, gd_offset + 0x0, 3)  # block bitmap
    struct.pack_into("<I", image, gd_offset + 0x4, 4)  # inode bitmap
    struct.pack_into("<I", image, gd_offset + 0x8, 5)  # inode table
    struct.pack_into("<H", image, gd_offset + 0xC, total_blocks - len(used_blocks))
    struct.pack_into("<H", image, gd_offset + 0xE, inodes_count - len(used_inodes))
    struct.pack_into("<H", image, gd_offset + 0x10, 1)

    # Block bitmap (block 3)
    block_bitmap_offset = 3 * block_size
    block_bitmap = bytearray(block_size)
    for block in used_blocks:
        byte_index = block // 8
        bit_index = block % 8
        block_bitmap[byte_index] |= 1 << bit_index
    image[block_bitmap_offset : block_bitmap_offset + block_size] = block_bitmap

    # Inode bitmap (block 4)
    inode_bitmap_offset = 4 * block_size
    inode_bitmap = bytearray(block_size)
    for inode_id in used_inodes:
        idx = inode_id - 1
        inode_bitmap[idx // 8] |= 1 << (idx % 8)
    image[inode_bitmap_offset : inode_bitmap_offset + block_size] = inode_bitmap

    # Inode table (blocks 5-8)
    inode_table_offset = 5 * block_size

    def write_inode(index: int, data: bytes) -> None:
        offset = inode_table_offset + (index - 1) * inode_size
        image[offset : offset + len(data)] = data

    # Root directory inode (#2)
    root_inode = bytearray(inode_size)
    struct.pack_into("<H", root_inode, 0x0, 0x41ED)  # directory with 755 perms
    struct.pack_into("<I", root_inode, 0x4, block_size)
    block_units = block_size // 512
    struct.pack_into("<I", root_inode, 0x1C, block_units)
    struct.pack_into("<I", root_inode, 0x28, 9)  # first direct block
    struct.pack_into("<H", root_inode, 0x1A, 2)
    write_inode(2, root_inode)

    # File inode (#12)
    file_inode = bytearray(inode_size)
    file_size = len(content)
    struct.pack_into("<H", file_inode, 0x0, 0x81A4)
    struct.pack_into("<I", file_inode, 0x4, file_size)
    allocated_blocks = 1 if file_size > 0 else 0
    struct.pack_into("<I", file_inode, 0x1C, allocated_blocks * block_units)
    struct.pack_into("<I", file_inode, 0x28, 10)
    struct.pack_into("<H", file_inode, 0x1A, 1)
    write_inode(12, file_inode)

    # Root directory data block (block 9)
    dir_block_offset = 9 * block_size
    dir_data = bytearray(block_size)

    def write_dir_entry(offset: int, inode: int, name: str, file_type: int, rec_len: int) -> None:
        encoded = name.encode("utf-8")
        dir_data[offset : offset + rec_len] = b"\x00" * rec_len
        struct.pack_into("<I", dir_data, offset, inode)
        struct.pack_into("<H", dir_data, offset + 4, rec_len)
        dir_data[offset + 6] = len(encoded)
        dir_data[offset + 7] = file_type
        dir_data[offset + 8 : offset + 8 + len(encoded)] = encoded

    write_dir_entry(0, 2, ".", 2, 12)
    write_dir_entry(12, 2, "..", 2, 12)
    name = "hello.txt"
    remaining = block_size - 24
    write_dir_entry(24, 12, name, 1, remaining)
    image[dir_block_offset : dir_block_offset + block_size] = dir_data

    # File data block (block 10)
    data_block_offset = 10 * block_size
    image[data_block_offset : data_block_offset + len(content)] = content

    path.write_bytes(bytes(image))


def build_hfsplus_image(path: Path, *, content: bytes = b"Hello HFS") -> None:
    """Create a simplified HFS-style image for testing."""

    block_size = 512
    total_blocks = 128
    catalog_start = 4
    catalog_blocks = 2
    data_start = 10

    image = bytearray(block_size * total_blocks)

    header = struct.pack(">4sIIII", b"AFS0", block_size, total_blocks, catalog_start, catalog_blocks)
    image[0 : len(header)] = header

    file_blocks = (len(content) + block_size - 1) // block_size or 1
    file_size = len(content)

    catalog_entries = struct.pack(">I", 1)
    name_bytes = b"example.txt"
    catalog_entries += struct.pack(">H", 1)  # type
    catalog_entries += struct.pack(">H", len(name_bytes))
    catalog_entries += name_bytes
    catalog_entries += struct.pack(">Q", file_size)
    catalog_entries += struct.pack(">I", data_start)
    catalog_entries += struct.pack(">I", file_blocks)

    catalog_padded = catalog_entries.ljust(catalog_blocks * block_size, b"\x00")
    start_catalog = catalog_start * block_size
    image[start_catalog : start_catalog + len(catalog_padded)] = catalog_padded

    data_offset = data_start * block_size
    image[data_offset : data_offset + len(content)] = content

    path.write_bytes(bytes(image))
