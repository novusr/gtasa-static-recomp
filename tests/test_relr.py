"""Build and exercise only the pure C++11 byte decoder; no ELF or guest calls."""

from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class RelrTests(unittest.TestCase):
    def test_synthetic_decoder(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = Path(directory) / 'relr'
            subprocess.run([
                'c++', '-std=c++11', '-Wall', '-Wextra', '-Wpedantic', '-Werror',
                '-I', str(ROOT / 'include'), str(ROOT / 'src/relr.cpp'),
                str(ROOT / 'tests/relr_test.cpp'), '-o', str(runner),
            ], check=True, capture_output=True)
            result = subprocess.run([str(runner)], check=True, capture_output=True, text=True)
            self.assertIn('RELR data-only checks passed:', result.stdout)


if __name__ == '__main__':
    unittest.main()
