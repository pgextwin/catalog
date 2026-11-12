"""Offline adversarial PGroonga original producer-run identity tests."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import issue112_pgroonga_producer_boundary as p


def run(kind):
    rid, attempt, path, _ = p.RUNS[kind]
    return dict(id=rid, run_attempt=attempt, path=path, head_branch="4.1.0",
                head_sha=p.COMMIT, event="push", status="completed",
                conclusion="success", actor={"login": "abetomo"})


def jobs(kind):
    wanted = p.WINDOWS_JOBS if kind == "windows" else {"GitHub": 113650372251}
    rows = []
    for key, number in wanted.items():
        steps = ("Configure Groonga", "Package") if kind == "windows" else (
            "Download artifacts", "Publish")
        rows.append(dict(id=number, name="PostgreSQL " + key if kind == "windows" else "GitHub",
                         head_sha=p.COMMIT, run_attempt=p.RUNS[kind][1],
                         status="completed", conclusion="success",
                         steps=[{"name": n, "conclusion": "success"} for n in steps]))
    for index in range((6 if kind == "windows" else 4) - len(rows)):
        rows.append({"id": 1000000 + index, "name": "unrelated"})
    return {"jobs": rows, "total_count": len(rows)}


def artifacts():
    rows = [dict(name="release-postgresql-" + pg + "-x64",
                 id=rec[0], size_in_bytes=rec[1],
                 digest="sha256:" + rec[2], expired=False,
                 workflow_run={"id": p.RUNS["windows"][0]})
            for pg, rec in p.ARTIFACTS.items()]
    rows.append({"name": "postgresql-18-x64-groonga-main", "id": 11590673721})
    return {"artifacts": rows, "total_count": 6}


class OriginalProducerBoundary(unittest.TestCase):
    def test_tag_signed_status_and_pinned_annotated_object(self):
        ref = {"ref": "refs/tags/4.1.0", "object": {"type": "tag", "sha": p.TAG}}
        tag = {"sha": p.TAG, "tag": "4.1.0",
               "object": {"type": "commit", "sha": p.COMMIT},
               "verification": {"verified": False, "reason": "unsigned"}}
        self.assertFalse(p.validate_tag(ref, tag)["tagSigned"])
        for mutated in (
            (dict(ref, ref="refs/tags/other"), tag),
            (ref, dict(tag, object={"type": "commit", "sha": "0" * 40})),
            (ref, dict(tag, verification={"verified": True, "reason": "valid"}))):
            with self.assertRaises(ValueError):
                p.validate_tag(*mutated)

    def test_run_attempt_event_actor_sha_and_conclusion_not_substitutable(self):
        for kind in p.RUNS:
            p.validate_run(run(kind), kind)
            for key, invalid in (("event", "workflow_dispatch"),
                                 ("run_attempt", 1 if kind == "release" else 2),
                                 ("head_sha", "0" * 40), ("conclusion", "skipped")):
                r = run(kind)
                r[key] = invalid
                with self.subTest(kind=kind, field=key), self.assertRaises(ValueError):
                    p.validate_run(r, kind)
            r = run(kind)
            r["actor"]["login"] = "untrusted"
            with self.assertRaises(ValueError):
                p.validate_run(r, kind)

    def test_original_step_failures_and_duplicate_jobs_rejected(self):
        for kind in p.RUNS:
            self.assertTrue(p.validate_jobs(jobs(kind), kind))
            r = jobs(kind)
            r["jobs"][0]["steps"][0]["conclusion"] = "skipped"
            with self.assertRaises(ValueError):
                p.validate_jobs(r, kind)
            r = jobs(kind)
            r["jobs"][0]["run_attempt"] = 9
            with self.assertRaises(ValueError):
                p.validate_jobs(r, kind)
            r = jobs(kind)
            r["jobs"][-1]["id"] = r["jobs"][0]["id"]
            with self.assertRaises(ValueError):
                p.validate_jobs(r, kind)

    def test_outer_actions_archive_hashes_are_not_release_zip_hashes(self):
        self.assertEqual(len(p.validate_artifacts(artifacts())), 5)
        for field, forged in (("digest", "sha256:" + "0" * 64),
                              ("size_in_bytes", 0), ("id", 0), ("expired", True)):
            rows = artifacts()
            rows["artifacts"][0][field] = forged
            with self.subTest(field=field), self.assertRaises(ValueError):
                p.validate_artifacts(rows)
        rows = artifacts()
        rows["artifacts"][0]["workflow_run"]["id"] = 123
        with self.assertRaises(ValueError):
            p.validate_artifacts(rows)

    def test_forged_workflow_contents_even_with_claimed_sha_rejected(self):
        for kind in p.RUNS:
            source = dict(path=p.RUNS[kind][2], sha=p.RUNS[kind][3],
                          encoding="base64", content="Z2l0aHVi")
            with self.assertRaises(ValueError):
                p.validate_workflow(source, kind)

    def test_permissions_and_all_majors_remain_deny(self):
        self.assertEqual(set(p.WINDOWS_JOBS), set(p.ARTIFACTS))
        self.assertTrue(all(value is False for value in p.DENY.values()))


if __name__ == "__main__":
    unittest.main()
