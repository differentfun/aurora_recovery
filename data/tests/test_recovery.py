from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from data.models import (
    CarvedMatch,
    FileSignature,
    ResultKind,
    ResultStatus,
    ScanMode,
    ScanResult,
)
from data.recovery import RecoveryManager, sanitize_filename
from data.scanner import ScannerEngine
from data.tests.helpers import build_ext2_image, build_hfsplus_image


class RecoveryManagerTests(unittest.TestCase):
    def test_recover_scan_result_copies_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            source = base / "source.txt"
            source.write_text("hello world", encoding="utf-8")

            result = ScanResult(
                identifier="quick-1",
                display_name="source.txt",
                location=source,
                size_bytes=source.stat().st_size,
                modified_at=None,
                status=ResultStatus.RECOVERABLE,
                kind=ResultKind.EXISTING,
                origin=ScanMode.QUICK,
            )

            manager = RecoveryManager(default_directory=base / "out")
            recovered_path = manager.recover_scan_result(result)
            self.assertTrue(recovered_path.exists())
            self.assertEqual(recovered_path.read_text(encoding="utf-8"), "hello world")

    def test_recover_carved_match_extracts_range(self) -> None:
        signature = FileSignature(
            name="Test",
            extension=".bin",
            header=b"HEAD",
            footer=b"TAIL",
        )
        segment = b"HEADpayloadTAIL"
        payload = b"XX" + segment + b"YY"

        with tempfile.TemporaryDirectory() as tmpdir:
            image_path = Path(tmpdir) / "disk.img"
            image_path.write_bytes(payload)

            match = CarvedMatch(
                identifier="carve-1",
                source=image_path,
                signature=signature,
                offset_start=2,
                offset_end=2 + len(segment),
                size_bytes=len(segment),
                preview=segment[:8],
            )

            manager = RecoveryManager(default_directory=Path(tmpdir) / "recovered")
            recovered_path = manager.recover_carved_match(match)
            self.assertTrue(recovered_path.exists())
            self.assertEqual(recovered_path.read_bytes(), segment)

    def test_unique_destination_appends_suffix(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workdir = Path(tmpdir)
            source_dir = workdir / "input"
            source_dir.mkdir()
            source_file = source_dir / "sample.txt"
            source_file.write_text("data", encoding="utf-8")

            recovery_dir = workdir / "output"
            recovery_dir.mkdir()
            existing = recovery_dir / "sample.txt"
            existing.write_text("old", encoding="utf-8")

            result = ScanResult(
                identifier="quick-1",
                display_name="sample.txt",
                location=source_file,
                size_bytes=source_file.stat().st_size,
                modified_at=None,
                status=ResultStatus.RECOVERABLE,
                kind=ResultKind.EXISTING,
                origin=ScanMode.QUICK,
            )

            manager = RecoveryManager(default_directory=recovery_dir)
            recovered_path = manager.recover_scan_result(result)
            self.assertTrue(recovered_path.exists())
            self.assertNotEqual(recovered_path, existing)
            self.assertEqual(recovered_path.name, "sample_1.txt")
            self.assertEqual(recovered_path.read_text(encoding="utf-8"), "data")

    def test_sanitize_filename_removes_invalid_characters(self) -> None:
        self.assertEqual(sanitize_filename("  *illeg@l name?.txt  "), "illeg_l_name_.txt")

    def test_recover_scan_result_from_ext_filesystem(self) -> None:
        payload = b"Hello from EXT"
        with tempfile.TemporaryDirectory() as tmpdir:
            image_path = Path(tmpdir) / "ext.img"
            build_ext2_image(image_path, content=payload)

            engine = ScannerEngine(signatures=[], max_files=16)
            summary = engine.deep_scan(image_path, signatures=[], filesystem="ext")
            self.assertIsNotNone(summary.context)
            self.assertEqual(len(summary.filesystem_entries), 1)
            entry = summary.filesystem_entries[0]

            manager = RecoveryManager(default_directory=Path(tmpdir) / "out")
            manager.register_filesystem(summary.context.name, summary.context.handler)
            recovered_path = manager.recover_scan_result(entry)
            self.assertTrue(recovered_path.exists())
            self.assertEqual(recovered_path.read_bytes(), payload)

    def test_recover_scan_result_from_hfs_filesystem(self) -> None:
        payload = b"Hello from HFS"
        with tempfile.TemporaryDirectory() as tmpdir:
            image_path = Path(tmpdir) / "hfs.img"
            build_hfsplus_image(image_path, content=payload)

            engine = ScannerEngine(signatures=[], max_files=16)
            summary = engine.deep_scan(image_path, signatures=[], filesystem="hfs")
            self.assertIsNotNone(summary.context)
            self.assertEqual(len(summary.filesystem_entries), 1)
            entry = summary.filesystem_entries[0]

            manager = RecoveryManager(default_directory=Path(tmpdir) / "out")
            manager.register_filesystem(summary.context.name, summary.context.handler)
            recovered_path = manager.recover_scan_result(entry)
            self.assertTrue(recovered_path.exists())
            self.assertEqual(recovered_path.read_bytes(), payload)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
