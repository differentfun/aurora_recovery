from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from data.fs.fat import FATAnalyzer
from data.tests.helpers import build_fat16_image


class FATAnalyzerTests(unittest.TestCase):
    def test_scan_and_recover_fat16(self) -> None:
        payload = b"Recovered content"
        with tempfile.TemporaryDirectory() as tmpdir:
            image_path = Path(tmpdir) / "fat16.img"
            build_fat16_image(image_path, content=payload)

            analyzer = FATAnalyzer(image_path)
            results = analyzer.scan()
            self.assertEqual(len(results), 1)
            result = results[0]
            self.assertEqual(result.display_name, "HELLO.TXT")
            self.assertEqual(result.size_bytes, len(payload))
            self.assertEqual(result.metadata["filesystem"], "fat16")

            record_id = int(result.metadata["filesystem_record"])
            output_path = Path(tmpdir) / "output.bin"
            analyzer.recover_record(record_id, output_path)
            self.assertTrue(output_path.exists())
            self.assertEqual(output_path.read_bytes(), payload)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
