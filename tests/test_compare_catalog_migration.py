#!/usr/bin/env python3
"""Tests for scripts/compare_catalog_migration.py."""

import copy
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

import sys

sys.path.insert(0, str(ROOT / "scripts"))
import compare_catalog_migration
import identity_records
import package_ledger


def _run_git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        text=True,
        capture_output=True,
        check=True,
    )
    return proc.stdout.strip()


def _setup_synthetic_repo(repo: Path, extensions: tuple[str, ...] = ("pg_repack", "pg_hint_plan")) -> tuple[str, str]:
    """Create a synthetic repo matching pre-PR-3b commit before -> post-PR-3b commit after."""
    repo.mkdir(parents=True, exist_ok=True)
    _run_git(repo, "init", "-b", "main")
    _run_git(repo, "config", "user.name", "Test Bot")
    _run_git(repo, "config", "user.email", "test@example.invalid")

    for subdir in ("scripts", "schema", "site", "config"):
        shutil.copytree(ROOT / subdir, repo / subdir)
    shutil.copytree(ROOT / "external", repo / "external")

    # Seed with ALL identities and ledgers (or chosen subset) so external records align cleanly.
    chosen = list(extensions)
    all_identities: dict[str, dict] = {}
    for path in sorted((ROOT / "identities").glob("*.json")):
        ident = json.loads(path.read_text(encoding="utf-8"))
        if ident["intake"]["class"] == "research-only" or ident["name"] in chosen:
            all_identities[ident["name"]] = ident

    (repo / "identities").mkdir()
    (repo / "packages").mkdir()
    (repo / "extensions").mkdir()
    (repo / "landscape" / "extensions").mkdir(parents=True)

    for name in chosen:
        ledger = copy.deepcopy(package_ledger.read_record(ROOT / "packages" / f"{name}.json"))
        latest = copy.deepcopy(package_ledger.current_release(ledger))
        ledger["releases"] = [latest]
        (repo / "packages" / f"{name}.json").write_bytes(package_ledger.json_bytes(ledger))
        view = package_ledger.website_record(ledger)
        (repo / "extensions" / f"{name}.json").write_bytes(package_ledger.json_bytes(view))

    for name, ident in all_identities.items():
        (repo / "identities" / f"{name}.json").write_text(
            json.dumps(ident, indent=2) + "\n", encoding="utf-8"
        )
        proj = identity_records.project_landscape_v1(ident)
        (repo / "landscape" / "extensions" / f"{name}.json").write_text(
            json.dumps(proj, indent=2) + "\n", encoding="utf-8"
        )

    v3_idx = identity_records.build_index_v3(all_identities)
    v2_idx = {"schemaVersion": 2, "extensions": sorted(chosen)}
    (repo / "index.json").write_text(json.dumps(v2_idx, indent=2) + "\n", encoding="utf-8")
    (repo / "identities" / "index.candidate.json").write_text(
        json.dumps(v3_idx, indent=2) + "\n", encoding="utf-8"
    )
    (repo / "landscape" / "index.json").write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "extensions": sorted(all_identities),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    # Pre-PR-3b shim for build_pages.py so synthetic pre-migration commits render Pages cleanly
    # in shallow clones without relying on historical blobs from git object history.
    real_build_pages = (repo / "scripts" / "build_pages.py").read_text(encoding="utf-8")
    shim = (
        "import json, shutil, subprocess, sys, tempfile\n"
        "from pathlib import Path\n"
        "repo_root = Path(__file__).resolve().parent.parent\n"
        "with tempfile.TemporaryDirectory() as td:\n"
        "    mirror = Path(td) / 'repo'\n"
        "    shutil.copytree(repo_root, mirror, ignore=shutil.ignore_patterns('.git'))\n"
        "    shutil.copy2(repo_root / 'identities' / 'index.candidate.json', mirror / 'index.json')\n"
        "    shutil.copy2(" + repr(str(ROOT / "scripts" / "build_pages.py")) + ", mirror / 'scripts' / 'build_pages.py')\n"
        "    git_dir = subprocess.check_output(['git', '-C', str(repo_root), 'rev-parse', '--absolute-git-dir'], text=True).strip()\n"
        "    (mirror / '.git').write_text('gitdir: ' + git_dir + '\\n', encoding='utf-8')\n"
        "    args = [sys.executable, str(mirror / 'scripts' / 'build_pages.py')]\n"
        "    for i, a in enumerate(sys.argv[1:]):\n"
        "        args.append(str(mirror / 'site' / 'inputs.json') if i > 0 and sys.argv[i] == '--inputs' else a)\n"
        "    proc = subprocess.run(args, cwd=str(mirror), check=True, text=True, capture_output=True)\n"
        "    sys.stdout.write(proc.stdout)\n"
    )
    (repo / "scripts" / "build_pages.py").write_text(shim, encoding="utf-8")

    _run_git(repo, "add", ".")
    _run_git(repo, "commit", "-m", "initial real admissions")
    before_sha = _run_git(repo, "rev-parse", "HEAD")

    # Migration commit (format-only): formalize v3 index.json, restore real build_pages.py, delete legacy views.
    (repo / "index.json").write_text(json.dumps(v3_idx, indent=2) + "\n", encoding="utf-8")
    (repo / "identities" / "index.candidate.json").unlink()
    shutil.rmtree(repo / "extensions")
    shutil.rmtree(repo / "landscape")
    (repo / "scripts" / "build_pages.py").write_text(real_build_pages, encoding="utf-8")
    _run_git(repo, "add", "-A")
    _run_git(repo, "commit", "-m", "PR-3b formalization")
    after_sha = _run_git(repo, "rev-parse", "HEAD")
    _run_git(repo, "update-ref", "refs/remotes/origin/main", after_sha)
    return before_sha, after_sha


class CompareCatalogMigrationTests(unittest.TestCase):
    def test_equal_migration_and_replay_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            repo = tmp_path / "repo"
            out_dir = tmp_path / "evidence"
            before_sha, after_sha = _setup_synthetic_repo(repo)

            diff_doc, replay_doc, code = compare_catalog_migration.compare_migration(
                repo, before_sha, after_sha, out_dir, effective_date="2026-11-25"
            )
            self.assertEqual(0, code, json.dumps({"diff": diff_doc, "replay": replay_doc}, indent=2))
            self.assertEqual("equal", diff_doc["verdict"])
            self.assertEqual("pass", replay_doc["verdict"])
            self.assertEqual(11, len(diff_doc["categories"]))
            self.assertTrue(all(c["equal"] for c in diff_doc["categories"].values()))
            self.assertTrue(all(c["verdict"] == "equal" for c in diff_doc["categories"].values()))
            self.assertEqual("noop", diff_doc["categories"]["publication_noop_verdict"]["publicationDecision"])
            self.assertTrue(diff_doc["categories"]["rendered_site_and_counts"]["renderedIdsEqual"])
            self.assertEqual(
                ["pg_hint_plan", "pg_repack"],
                diff_doc["categories"]["rendered_site_and_counts"]["renderedDistributedIds"],
            )
            self.assertTrue(all(c["verdict"] == "pass" for c in replay_doc["categories"].values()))
            self.assertEqual(
                before_sha,
                replay_doc["extensions"]["pg_repack"]["latestRealAdmissionCommit"],
            )
            self.assertNotEqual(
                after_sha,
                replay_doc["extensions"]["pg_repack"]["latestRealAdmissionCommit"],
            )
            self.assertTrue(replay_doc["subsequentUpdateExercises"]["passed"])
            self.assertTrue((out_dir / "catalog-c-migration-diff.json").is_file())
            self.assertTrue((out_dir / "catalog-c-admission-replay.json").is_file())

    def test_injected_description_diff_fails_nonzero(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            repo = tmp_path / "repo"
            out_dir = tmp_path / "evidence"
            before_sha, after_sha = _setup_synthetic_repo(repo)

            # Mutate pg_repack identity description override at after.
            ident_path = repo / "identities" / "pg_repack.json"
            ident = json.loads(ident_path.read_text(encoding="utf-8"))
            ident["research"]["descriptionOverride"] = "Mutated landscape summary"
            ident_path.write_text(json.dumps(ident, indent=2) + "\n", encoding="utf-8")
            _run_git(repo, "add", "identities/pg_repack.json")
            _run_git(repo, "commit", "-m", "inject description drift")
            bad_after = _run_git(repo, "rev-parse", "HEAD")
            _run_git(repo, "update-ref", "refs/remotes/origin/main", bad_after)

            diff_doc, _, code = compare_catalog_migration.compare_migration(
                repo, before_sha, bad_after, out_dir, effective_date="2026-11-25"
            )
            self.assertEqual(1, code)
            self.assertEqual("diff", diff_doc["verdict"])
            self.assertFalse(diff_doc["categories"]["descriptions_both_sets"]["equal"])
            self.assertEqual("diff", diff_doc["categories"]["descriptions_both_sets"]["verdict"])
            self.assertFalse(diff_doc["categories"]["rendered_site_and_counts"]["equal"])
            self.assertEqual("diff", diff_doc["categories"]["rendered_site_and_counts"]["verdict"])

    def test_invalid_commit_returns_exit_code_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            code = compare_catalog_migration.main(
                [
                    "--before",
                    "0" * 40,
                    "--after",
                    "HEAD",
                    "--output",
                    tmp,
                    "--repo",
                    str(ROOT),
                ]
            )
            self.assertEqual(2, code)


if __name__ == "__main__":
    unittest.main()
