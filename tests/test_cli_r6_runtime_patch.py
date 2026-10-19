"""Guard Windows CLI runtime patch level before public release."""
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]


class RuntimePinTests(unittest.TestCase):
    def test_same_exact_sdk_pin_for_all_cli_build_paths(self):
        for file in ("global.json","dotnet/global.json"):
            with self.subTest(file=file):
                sdk=json.loads((ROOT/file).read_text(encoding="utf-8"))["sdk"]
                self.assertEqual(sdk["version"],"10.0.402")
                self.assertEqual(sdk["rollForward"],"disable")
        for file in (".github/workflows/validate.yml",
                     ".github/workflows/cli-candidate.yml"):
            with self.subTest(file=file):
                text=(ROOT/file).read_text(encoding="utf-8")
                self.assertIn("dotnet-version: '10.0.402'",text)
                self.assertIn("-p:RuntimeFrameworkVersion=10.0.13",text)
                self.assertNotIn("dotnet-version: '10.0.100'",text)

    def test_original_r6_receipt_requires_patched_sdk(self):
        src=(ROOT/"scripts/cli_r6_candidate.py").read_text(encoding="utf-8")
        self.assertIn('record["sdkObserved"] != "10.0.402"',src)


if __name__=="__main__":
    unittest.main()
