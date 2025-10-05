from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from data.models import FileSignature
from data.scanner import ScannerEngine
from data.tests.helpers import build_ext2_image, build_fat16_image, build_hfsplus_image


class ScannerEngineTests(unittest.TestCase):
    def test_quick_scan_lists_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            file_path = base / "example.txt"
            file_path.write_text("sample data", encoding="utf-8")

            engine = ScannerEngine(max_files=10)
            results = engine.quick_scan(base, recursive=False)
            self.assertEqual(len(results), 1)
            result = results[0]
            self.assertEqual(result.display_name, "example.txt")
            self.assertEqual(result.size_bytes, len("sample data"))
            self.assertEqual(str(result.location), str(file_path))

    def test_deep_scan_detects_signature(self) -> None:
        signature = FileSignature(
            name="Test",
            extension=".bin",
            header=b"HEAD",
            footer=b"TAIL",
        )

        payload = b"zzHEADimportant_payloadTAILyy"
        with tempfile.TemporaryDirectory() as tmpdir:
            image_path = Path(tmpdir) / "disk.img"
            image_path.write_bytes(payload)

            engine = ScannerEngine(signatures=[signature])
            summary = engine.deep_scan(image_path)
            matches = summary.carved
            self.assertEqual(len(matches), 1)
            match = matches[0]
            self.assertEqual(match.offset_start, payload.find(signature.header))
            segment = payload[match.offset_start : match.offset_end]
            self.assertTrue(segment.startswith(signature.header))
            self.assertTrue(segment.endswith(signature.footer))
            self.assertEqual(segment, b"HEADimportant_payloadTAIL")
            self.assertEqual(match.size_bytes, len(segment))
            self.assertIs(match.signature, signature)

    def test_deep_scan_handles_chunk_boundary(self) -> None:
        signature = FileSignature(
            name="Boundary",
            extension=".bin",
            header=b"ABCD",
            footer=b"WXYZ",
        )

        payload = b'00000A' + b'BCD12W' + b'XYZtail'
        with tempfile.TemporaryDirectory() as tmpdir:
            image_path = Path(tmpdir) / "image.bin"
            image_path.write_bytes(payload)

            engine = ScannerEngine(signatures=[signature], chunk_size=6)
            summary = engine.deep_scan(image_path)
            matches = summary.carved
            self.assertEqual(len(matches), 1)
            match = matches[0]
            header_index = payload.find(signature.header)
            footer_index = payload.find(signature.footer)
            expected_segment = payload[header_index : footer_index + len(signature.footer)]
            self.assertEqual(match.offset_start, header_index)
            self.assertEqual(match.offset_end, footer_index + len(signature.footer))
            self.assertEqual(match.size_bytes, len(expected_segment))
            self.assertEqual(match.preview, expected_segment)
            self.assertIs(match.signature, signature)

    def test_deep_scan_respects_signature_filter(self) -> None:
        jpeg = FileSignature(
            name="JPEG",
            extension=".jpg",
            header=bytes.fromhex("ffd8"),
            footer=bytes.fromhex("ffd9"),
        )
        png = FileSignature(
            name="PNG",
            extension=".png",
            header=bytes.fromhex("89504e470d0a1a0a"),
            footer=bytes.fromhex("49454e44ae426082"),
        )
        payload = jpeg.header + b"jpeg-data" + jpeg.footer + png.header + b"png-data" + png.footer

        with tempfile.TemporaryDirectory() as tmpdir:
            image_path = Path(tmpdir) / "disk.img"
            image_path.write_bytes(payload)

            engine = ScannerEngine(signatures=[jpeg, png])
            summary = engine.deep_scan(image_path, signatures=[jpeg])
            matches = summary.carved
            self.assertEqual(len(matches), 1)
            self.assertIs(matches[0].signature, jpeg)

    def test_deep_scan_collects_fat_filesystem(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            image_path = Path(tmpdir) / "fat16.img"
            build_fat16_image(image_path, content=b"file contents")

            engine = ScannerEngine(signatures=[], max_files=10)
            summary = engine.deep_scan(image_path, signatures=[], filesystem="fat")
            self.assertIsNotNone(summary.context)
            self.assertEqual(summary.context.name, "fat16")
            self.assertEqual(len(summary.filesystem_entries), 1)
            result = summary.filesystem_entries[0]
            self.assertEqual(result.display_name, "HELLO.TXT")
            self.assertEqual(result.metadata["filesystem"], "fat16")

    def test_deep_scan_collects_ext_filesystem(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            image_path = Path(tmpdir) / "ext2.img"
            build_ext2_image(image_path, content=b"ext contents")

            engine = ScannerEngine(signatures=[], max_files=10)
            summary = engine.deep_scan(image_path, signatures=[], filesystem="ext")
            self.assertIsNotNone(summary.context)
            self.assertEqual(summary.context.name, "ext2")
            self.assertEqual(len(summary.filesystem_entries), 1)
            result = summary.filesystem_entries[0]
            self.assertEqual(result.display_name, "hello.txt")
            self.assertEqual(result.metadata["filesystem"], "ext2")

    def test_deep_scan_ext_filter_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            image_path = Path(tmpdir) / "ext2.img"
            build_ext2_image(image_path, content=b"ext contents")

            engine = ScannerEngine(signatures=[], max_files=10)
            summary = engine.deep_scan(image_path, signatures=[], filesystem="ext4")
            self.assertEqual(len(summary.filesystem_entries), 0)
            self.assertIsNone(summary.context)

    def test_deep_scan_collects_hfs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            image_path = Path(tmpdir) / "hfs.img"
            build_hfsplus_image(image_path, content=b"apple contents")

            engine = ScannerEngine(signatures=[], max_files=10)
            summary = engine.deep_scan(image_path, signatures=[], filesystem="hfs")
            self.assertIsNotNone(summary.context)
            self.assertEqual(summary.context.name, "hfs")
            self.assertEqual(len(summary.filesystem_entries), 1)
            entry = summary.filesystem_entries[0]
            self.assertEqual(entry.display_name, "example.txt")
            self.assertEqual(entry.metadata["filesystem"], "hfs")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
