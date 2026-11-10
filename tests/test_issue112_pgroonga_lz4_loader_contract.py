"""Offline safety contract; nonpublishing dynamic EDB loader probe."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/issue112-pgroonga-lz4-loader.ps1'
WORKFLOW = ROOT / '.github/workflows/issue112-pgroonga-lz4-loader.yml'

class LoaderContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.script = SCRIPT.read_text(encoding='utf-8')
        cls.workflow = WORKFLOW.read_text(encoding='utf-8')

    def test_exact_original_pins_for_all_majors(self):
        for major, digest in {
            '14':'39d2685f234c8b45563f57f113bd8c84cc1ae4e8c0c22e6826bf168ba1c0ab39',
            '15':'fbc73734028b0b2372a6ee6538863999c2f9f06ec9f1be633ac460c7d8a0d4f1',
            '16':'40c71f7890e6ceb46f79fdc10e596da21bfb622f7c9d1f8be7784175d96df7e8',
            '17':'dcbd356ab8a7c8fc3a3cc7082b4f99a1884b5a68674e25ef4bbe56583c38147b',
            '18':'3ccbfaf771ec7a0edf61dabe0eb60188dcc22feff8449a7e96afdb87641630ab',
        }.items():
            self.assertIn(f"'{major}' =", self.script)
            self.assertIn(digest, self.script)

    def test_live_path_and_pid_necessary_not_basename(self):
        for item in ('Test-LoadedModuleSet', 'OrdinalIgnoreCase', 'Get-Process -Name postgres',
                     'pgroonga.dll', 'libgroonga.dll', 'liblz4.dll', 'Get-FileHash',
                     "if ($null -eq $observedPid)", 'Get-AuthenticodeSignature'):
            self.assertIn(item, self.script)
        self.assertIn('cross-process self-test failed', self.script)
        self.assertIn('wrong-path self-test failed', self.script)

    def test_workflow_is_readonly_nonpublishing_and_separate(self):
        self.assertIn('contents: read', self.workflow)
        self.assertNotIn('workflow_dispatch:', self.workflow)
        for fragment in ('ref: 07449a2384ae4e2fc01820e263ed4bc45cd73abf',
                         "- pg: '14'", "- pg: '18'", 'persist-credentials: false',
                         'PUBLIC_GET=DENY', 'ORIGINAL_ZIP_UPLOAD=NONE'):
            self.assertIn(fragment, self.workflow)
        for banned in ('upload-artifact', 'create-release', 'release: write', 'attest-build-provenance'):
            self.assertNotIn(banned, self.workflow)

if __name__=='__main__':
    unittest.main()
