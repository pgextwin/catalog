# pgextwin CLI — public-release track (Issue #112)

Status: **nonpublishing implementation track**, 2026-10-17 JST. Primary policy: [build #112](https://github.com/pgextwin/build/issues/112); signed-Publisher dependencies: [build #75](https://github.com/pgextwin/build/issues/75).

## Product boundary

The intended CLI is a **single Windows x64 .NET self-contained executable** named `pgextwin.exe`. The final product can generate one portable offline ZIP **locally, per PostgreSQL major**, from independently verified *existing* official Release assets. No centrally prebuilt all-extension bundle Release is part of this plan. A CLI binary release and a newly authorized extension/bundle distribution are separate decisions and evidence sets.

Current Catalog CLI has only local, explicitly **UNVERIFIED** `list` / `search` and a separately pinned GET-only single-asset `download` returning `INTEGRITY_ONLY`. The existing in-memory synthetic ZIP library and detached P1 report handoff are deliberately not installed CLI functionality. It does not currently provide trusted `verify`, local bundle creation, offline reader, installer dry-run or apply. Do not describe it as a trustworthy installer.

## Ordered deliverables and acceptance

| Gate | Deliverable | Acceptance evidence | Current state |
| --- | --- | --- | --- |
| CLI-R0 | Immutable P0 Catalog/coverage CLI inventory | Real subprocess JSON 70 rows, 65 RECORD_ONLY, 5 DENY, major-complete false; required CI/postmerge | **PASS**, Catalog PR #98 / main `cc434a7c...` |
| CLI-R1 | Portable executable private rehearsal | On a Windows runner, produce **self-contained win-x64, single-file** `pgextwin.exe`, capture size/SHA256 and exercise real `--help`, PG18 14-row `list`, `search`, missing-Catalog and missing-independent-policy DENY/exit 2 | **In PR**, requires successful App15368 `validate` plus `cli-windows-package-smoke` |
| CLI-R2 | Authenticated online `verify` | Independently authenticated policy/Trusted Root, exact Catalog and original Release IDs, full GitHub SLSA and SPDX Sigstore verification, independent negative tests and absence of trust downgrade | **R2a signed P1 report claim authentication in progress; genuine Sigstore R2 still TODO** |
| CLI-R3 | CLI-produced per-major offline ZIP and offline `verify` | Local-only output, original byte-equal assets, canonical manifest, exact externally authenticated trust anchor, offline network-denial test, ZIP safety/coverage checks; incomplete major cannot claim COMPLETE | **BLOCKED on trust gate**, fixture-only ZIP already exists |
| CLI-R4 | `install --dry-run` | Shared online/offline plan, server major/arch/path, preload/background-worker/reporting, PG14 historical lifecycle, PG19 not assumed; no filesystem/server mutation | **TODO** |
| CLI-R5 | Explicit transactional `install --apply` | Separate owner authorization, staging, backups, no overwrites or hidden restarts/SQL, interruption rollback on disposable Windows PostgreSQL | **BLOCKED pending separate gate** |
| CLI-R6 | CLI binary *release* preparation | Reproducible release configuration, source commit/SDK/runtime pin, binary SHA256, malware/license/SBOM review, provenance and independently verified binary signature or approved trust channel, clean-machine smoke, rollback procedure | **TODO** |
| CLI-R7 | Public `pgextwin` CLI release and site/docs | Explicit CLI-publication decision **after R6**, unique create-only version/tag, signed original binary assets, SHA256/verification instructions and EN/JA website links; no unverified claim about package/bundle install rights | **NOT AUTHORIZED** |
| CLI-R8 | Trusted whole-fleet online/offline launch | Formal P1 70/70 with successful original publication chain, #75 GO B/G4/G5 as applicable, independently accepted offline trust, PG-major coverage and E2E | **BLOCKED** |

R1 CI rehearsal is **ephemeral/private**: no Actions Artifact upload, GitHub Release, tag, package installer, secret, deployment, code-signing request, or unreviewed publication. This is a compilation/runtime test of one executable, not R6 acceptance.

## Immutable state and blockers

- Historical formal P1 **65/70**, separate source proof **40/40**, `plpgsql_check` PG14–18 **five DENY**. Historical Release ID 409572202 has no proven original PUBLISH-to-publish-success causal bridge; do not reclassify failed Run 38128142145.
- #75 signed Publisher positive prewrite, credential isolation and external transitive closure remain **NOT PROVEN**. GO B/G4/G5 are **NO-GO**. No new extension Release/public distribution without accepted authorization.
- CLI-generated unsigned offline ZIP is a user's local derivative; checksums embedded inside the ZIP cannot authenticate its origin. Out-of-band trust root, genuine bytes and attestation verification remain mandatory.
- PG14 becomes historical after 2026-11-12; PG19 must not become maintained by assuming release-candidate availability. Adopt PG19 only after GA and approved compatibility/CI/signature matrix.
- Published extension ZIPs and Catalog/Website history are unchanged. No existing Release/tag, signer/Publisher pin, Secret, branch protection, budget or GitHub App permission change is authorized by this document.

## Progression without repeated Work handoffs

Implement one scoped, nonpublishing PR per independently testable unit. Require current-head protected-main `validate` App 15368 success, plus any focused Windows smoke required for that change. Merge only after reviewing complete changed paths and exact head; verify postmerge main and records. Reuse prior 65/70 original-byte and 40/40 source evidence rather than recomputing it when code changes do not change those trust facts. Treat failures as failures and fix root cause before proceeding. Record completed gates with exact PR/Run/job IDs in build Issue #112.

The public binary decision must review the concrete `pgextwin.exe`, its origin/pins, security validation, and verification instructions. The CLI may ship a clearly restricted preview before R8 **only if separately authorized and R6 has passed**, and it must keep unverified package download/install behavior disabled or conspicuously denied. This plan itself never authorizes a publish.
