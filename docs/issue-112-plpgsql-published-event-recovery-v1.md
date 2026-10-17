# Issue #112 — plpgsql_check exact published-Event recovery profile (pending v1)

**Status: BLOCKED / NOT FORMALLY ACCEPTED.** The protected P1 v5 65/70 ledger and separately sealed historical source v2 40/40 remain unchanged. P1 BLOCKED, P2 NO-GO, publication and distribution denied. This work is a nonpublishing fail-closed evidence intake, not a release operation or run-failure waiver.

## Immutable-only identity

- Repository `pgextwin/plpgsql_check`, numeric ID `1410581312`
- Release ID `409572202`, tag `v2.10.14-windows.1`, packaging SHA `37cb5ee00f556fd6b57e439a5e19cd210125a571`
- Original Promotion `38128142145`, attempt 1, **FAILURE**; Publish Job `114438997591`, **FAILURE**. PG14–18 Build Jobs `114436765036/114436765058/114436765083/114436765086/114436765070` independently **SUCCESS**
- Original PUBLISH approval Artifact `11698050284`, exact transported ZIP SHA256 `132e7bad81707344e8fd9d433cde4a161144417b843620c684ae8088615d8856`; recovery Artifact `11698336665`, exact ZIP SHA256 `5316ef1674098697da65bf9780390e313ff8da9a61db2def86c2b72ad765dfd6` (DRAFT_STAGED, *not* published)
- GET-only operator's observation reports ReleaseEvent `16939274945`, type ReleaseEvent / action published / actor `github-actions[bot]` ID `41898282` / published at `2026-10-11T10:46:26Z`, same numeric Release/tag/SHA. Endpoint: [events page 2](https://api.github.com/repos/pgextwin/plpgsql_check/events?per_page=100&page=2). **This chat's GitHub connector refuses the Events API endpoint**. No claim is made that its raw bytes have yet been independently obtained here.
- GitHub REST current published Release metadata and all 16 published assets have been independently reobserved; prior read-only audit checks documented the original PG build outputs against 15 corresponding Release asset hashes. Neither metadata nor those prior receipts substitute for new independent genuine dual Sigstore checks.

## Safe implementation

`scripts/distribution_p1_plpgsql_event_recovery.py` is an **isolated** exact-identity contract. It does not edit `distribution_release_verify_p1.py::signed_run`, `distribution_p1_batch.py::fetch_jobs`, the existing formal ledger, or the Publisher. It rejects changed actor, event type/action/target, replayed tag, draft, event time, missing Release asset, failed build, forged Run/Publish SUCCESS, duplicate jobs and altered original artifact transport hashes.

A separately scoped, allowlisted **GET-only** candidate-capture command:

```bash
python scripts/distribution_p1_plpgsql_event_recovery.py \
  --capture-event --output /safe-temp/event-canonical.json
```

reads only pages 1–3 of the official repository Events API. It never calls PATCH, workflow dispatch, rerun, release creation, or release publication; it never accepts evidence or writes GitHub content. If the event has aged out or access fails, it exits DENY. It emits a deterministic sorted compact UTF-8 canonical projection and SHA256; the **event SHA remains NULL in the protected pending anchor** until the actual capture and independent verification have been completed. Snapshot position and submitted hash values are not trusted.

Archive hash validation of the two existing promotion Artifacts is a separate function; it verifies a single bounded JSON member and does not treat a transport digest as a signature. The separately exposed PG verifier requires the original exact public ZIP and an actual `gh attestation verify` result for **both SLSA v1 and SPDX 2.3**, using authenticated TUF root and exact signer SHA, run ID and attempt. Neither Event nor receipt can stand in for these signed predicates.

## Remaining gates — all required for a future new append-only acceptance ledger

1. Capture original ReleaseEvent through independent official GET, verify Repo ID, actor ID, action, time, Release ID, tag, target SHA and draft status; independently record exact canonical snapshot digest in a new protected evidence version.
2. Obtain and actually hash/parse both original approval and DRAFT_STAGED recovery archives, independently verify five original Build Artifacts' internal original ZIP/SPDX/Grype bytes and all 16 formal Release Assets, with numeric IDs against sealed policy.
3. Independently verify actual original PG14–18 ZIP dual attestation using *official pinned gh* and TUF root. Signed predicates must reference exact source, signer, Run 38128142145 / attempt 1; never reinterpret the Run or its Publisher as success.
4. **Bridge missing:** the observed ReleaseEvent is proof of a publication event by `github-actions[bot]`; it is **not** proof of which credential/HTTP request performed the transition, or that the original manual PUBLISH approval authorized that later operation. Without separate authenticated causal authorization-to-publication evidence, formal acceptance stays DENY even with five genuine attestation passes. A self-declared `causalBridgeIndependentlyVerified=true` in candidate JSON is not an independent proof. Human identity is not intrinsically required, but a genuine binding is.
5. Only after a protected code-reviewable exact bridge validator, signed five-row re-verification, separately audited per-PG receipts and mandatory App15368 checks may a **new append-only** formal P1 v6 be considered; v5 and independent source v2 must remain byte-identical. P2 and distribution remain separate gates.

`evidence/p1/plpgsql-published-event-recovery-pending-v1.json` deliberately contains `null` event/causal SHA and `false` verified status. It must never be read as an acceptance ledger or a source of trust. Tests are synthetic adversarial regressions only, not signature verification. Any protected-main candidate capture must be explicitly labeled OBSERVATION_ONLY_NOT_ACCEPTED.

**Forbidden:** Release/tag/signature creation, republishing, Dispatch/Re-run, token/Secret disclosure, protection or CI bypass, accepting an unproven HTTP method/credential/human, or distribution installation.
