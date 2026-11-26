#!/usr/bin/env python3
"""build_pages.render_cli_included_items: standalone multi-architecture labels.

Two standalone records for the same item and version (e.g. psqlODBC x64 and
x86 MSIs) must render as distinct lines carrying the architecture parsed
from assetName; a lone record keeps its historical label without a suffix.
"""
from pathlib import Path
import sys
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import build_pages


def driver_record(asset_name, version="18.00.0006"):
    return {
        "item": "psqlodbc",
        "category": "drivers",
        "pgMajor": None,
        "upstreamVersion": version,
        "assetName": asset_name,
    }


class CliIncludedItemsArchTests(TestCase):
    def test_two_architectures_render_distinct_lines_en(self):
        html = build_pages.render_cli_included_items(
            [],
            [driver_record("psqlodbc_x64.msi"), driver_record("psqlodbc_x86.msi")],
            "en",
        )
        self.assertIn("<li>Drivers: psqlODBC 18.00.0006 (x64)</li>", html)
        self.assertIn("<li>Drivers: psqlODBC 18.00.0006 (x86)</li>", html)

    def test_two_architectures_render_distinct_lines_ja(self):
        html = build_pages.render_cli_included_items(
            [],
            [driver_record("psqlodbc_x64.msi"), driver_record("psqlodbc_x86.msi")],
            "ja",
        )
        self.assertIn("<li>ドライバ：psqlODBC 18.00.0006（x64）</li>", html)
        self.assertIn("<li>ドライバ：psqlODBC 18.00.0006（x86）</li>", html)

    def test_single_record_keeps_plain_label(self):
        html = build_pages.render_cli_included_items(
            [], [driver_record("psqlodbc_13_02_0000-x64.zip", "13.02.0000")], "en"
        )
        self.assertEqual("<li>Drivers: psqlODBC 13.02</li>", html)


if __name__ == "__main__":
    main()
