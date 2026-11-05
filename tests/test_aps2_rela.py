"""Build and exercise only the pure C++11 byte decoder; no ELF or guest calls."""

from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class Aps2RelaTests(unittest.TestCase):
    def test_synthetic_decoder(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = Path(directory) / 'aps2-rela'
            subprocess.run([
                'c++', '-std=c++11', '-Wall', '-Wextra', '-Wpedantic', '-Werror',
                '-I', str(ROOT / 'include'), str(ROOT / 'src/aps2_rela.cpp'),
                str(ROOT / 'tests/aps2_rela_test.cpp'), '-o', str(runner),
            ], check=True, capture_output=True)
            result = subprocess.run([str(runner)], check=True, capture_output=True, text=True)
            self.assertIn('APS2 RELA data-only checks passed:', result.stdout)


if __name__ == '__main__':
    unittest.main()
