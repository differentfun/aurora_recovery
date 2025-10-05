from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
import struct

from data.fs.ext import ExtAnalyzer, ExtGeometry, ExtInode
from data.tests.helpers import build_ext2_image


class ExtAnalyzerTests(unittest.TestCase):
    def test_scan_and_recover_ext2(self) -> None:
        payload = b"Sample EXT data"
        with tempfile.TemporaryDirectory() as tmpdir:
            image_path = Path(tmpdir) / "ext2.img"
            build_ext2_image(image_path, content=payload)

            analyzer = ExtAnalyzer(image_path)
            results = analyzer.scan()
            self.assertEqual(len(results), 1)
            result = results[0]
            self.assertEqual(result.display_name, "hello.txt")
            self.assertEqual(result.size_bytes, len(payload))
            self.assertEqual(result.metadata["filesystem"], "ext2")

            record_id = int(result.metadata["filesystem_record"])
            destination = Path(tmpdir) / "out.bin"
            analyzer.recover_record(record_id, destination)
            self.assertTrue(destination.exists())
            self.assertEqual(destination.read_bytes(), payload)

    def test_extent_block_mapping(self) -> None:
        class FakeExtAnalyzer(ExtAnalyzer):
            def __init__(self) -> None:
                super().__init__(Path("unused"))
                self.geometry = ExtGeometry(
                    block_size=1024,
                    inode_size=128,
                    inodes_count=0,
                    blocks_count=0,
                    blocks_per_group=0,
                    inodes_per_group=0,
                    first_data_block=0,
                    group_count=0,
                    descriptor_size=32,
                    fs_type="ext4",
                )
            def _read_block_bytes(self, block: int) -> bytes:  # noqa: D401 - override
                return b""

        analyzer = FakeExtAnalyzer()
        header = struct.pack("<HHHHI", 0xF30A, 1, 4, 0, 0)
        entry = struct.pack("<IHHI", 0, 3, 0, 20)
        block_data = (header + entry).ljust(60, b"\x00")
        inode = ExtInode(
            inode_index=12,
            mode=0x81A4,
            size=3 * analyzer.geometry.block_size,
            blocks=0,
            flags=0x80000,
            block_pointers=tuple([0] * 15),
            block_data=block_data,
        )
        blocks = analyzer._file_blocks(inode)
        self.assertEqual(blocks, [20, 21, 22])

    def test_indirect_block_mapping(self) -> None:
        class FakeExtAnalyzer(ExtAnalyzer):
            def __init__(self, block_map: dict[int, bytes]) -> None:
                super().__init__(Path("unused"))
                self.geometry = ExtGeometry(
                    block_size=1024,
                    inode_size=128,
                    inodes_count=0,
                    blocks_count=0,
                    blocks_per_group=0,
                    inodes_per_group=0,
                    first_data_block=0,
                    group_count=0,
                    descriptor_size=32,
                    fs_type="ext3",
                )
                self._block_map = block_map

            def _read_block_bytes(self, block: int) -> bytes:  # noqa: D401
                return self._block_map.get(block, b"")

        single_indirect_entries = struct.pack("<8I", 50, 60, 0, 0, 0, 0, 0, 0)
        analyzer = FakeExtAnalyzer({100: single_indirect_entries})
        block_pointers = [0] * 15
        block_pointers[0] = 30
        block_pointers[12] = 100
        inode = ExtInode(
            inode_index=15,
            mode=0x81A4,
            size=3 * analyzer.geometry.block_size,
            blocks=0,
            flags=0,
            block_pointers=tuple(block_pointers),
            block_data=b"\x00" * 60,
        )
        blocks = analyzer._file_blocks(inode)
        self.assertEqual(blocks, [30, 50, 60])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
