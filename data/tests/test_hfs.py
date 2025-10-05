from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from data.fs.apple import AppleFSAnalyzer
from data.tests.helpers import build_hfsplus_image


class HFSAnalyzerTests(unittest.TestCase):
    def test_scan_and_recover_hfs(self) -> None:
        payload = b"Hello from HFS"
        with tempfile.TemporaryDirectory() as tmpdir:
            image_path = Path(tmpdir) / "hfs.img"
            build_hfsplus_image(image_path, content=payload)

            analyzer = AppleFSAnalyzer(image_path)
            results = analyzer.scan()
            self.assertEqual(len(results), 1)
            entry = results[0]
            self.assertEqual(entry.display_name, "example.txt")
            self.assertEqual(entry.size_bytes, len(payload))

            record_id = int(entry.metadata["filesystem_record"])
            output_path = Path(tmpdir) / "out.bin"
            analyzer.recover_record(record_id, output_path)
            self.assertTrue(output_path.exists())
            self.assertEqual(output_path.read_bytes(), payload)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
