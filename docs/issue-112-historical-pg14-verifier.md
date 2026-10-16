# Issue #112 — historical pg_bigm PG14 strict opt-in P1 profile

**Status: engineering/fixture acceptance only. This profile never authorizes
publication, P2, release promotion, aggregate archive or CLI installation.**

This is deliberately separate from
`distribution_release_verify_p1.py` / `distribution_release_audit_p1.py`.
The ordinary new-Release path still requires `immutable_source` with a
pre-existing full upstream SHA and the exact main/promote/workflow_dispatch
certificate, run and signer policy. Do not reuse the historical profile for a
new Release; no date/branch-name guessing and no fallback when normal checks
fail.

## Fixed row identity and trust boundary

Only pg_bigm PG14 is eligible: Catalog commit
`2e850bb5e5a3441edaa887fa5f7c378d22aea4c6`, repository numeric
`1405047175`, Release `408449466`, ZIP Asset `626562095`, original
ZIP SHA256 `3cd9f0facca96f185a406e795fd28a75acea60bb45ac531c9e06fcbc32e2277d`,
packaging SHA `cfbb52f8caf41b2c393a1a34f6011157979af2bb`,
run `38007421492` attempt **1**, old signer SHA
`8246f4d3415a48b1ad4af13f421277057886b58f`.
Original `.github/workflows/windows.yml` is push on
`refs/heads/release/v1.2-20250903-windows.2`; success requires
PG14 job `114079409058` and publish job `114082606852` success
from the **same attempt**. No current Promotion workflow or main identity
may be substituted.

The original pinned config includes the upstream tag
`pgbigm/pg_bigm@v1.2-20250903` and version `1.2`, **not** a full commit.
The original safe ZIP's signed PACKAGE-INFO claims
`735dceba0ecdd8ac1aaaaa207226a7102b6bbd71`.
Corroborate this with original PG14 checkout logs and the existence of
the upstream full Git commit object. Logs/commit-existence are *corroboration*,
not a cryptographic signature or proof that a mutable tag never changed.

## Single-PG14 private snapshot layout

Work collects **original** data over independent anonymous authenticated-TLS
GitHub GET and keeps the archive in a private local workspace. No discovery,
downloads, secrets, installation or publication occurs in the verifier.

```text
SNAPSHOT/
  index.json                  # Catalog exact commit, original bytes
  pg_bigm.json                # Catalog extensions/pg_bigm.json at exact commit
  release.json                # GET /repos/pgextwin/pg_bigm/releases/408449466
  extension.json              # config/extension.json at original packaging SHA
  windows.yml                 # .github/workflows/windows.yml at packaging SHA
  run.json                    # GET /actions/runs/38007421492
  jobs.json                   # GET /actions/runs/38007421492/attempts/1/jobs?per_page=100
  pg14-job.log                # GET logs of 114079409058 from original attempt
  upstream-commit.json        # GET /repos/pgbigm/pg_bigm/git/commits/735d...
  pg_bigm-v1.2-20250903-pg14-windows-x64.zip.jsonl
  assets/
    pg_bigm-v1.2-20250903-pg14-windows-x64.zip
    SHA256SUMS.txt
    pg_bigm-v1.2-20250903-pg14-windows-x64.spdx.json
    pg_bigm-v1.2-20250903-pg14-windows-x64.vulnerabilities.json
```

The ZIP and the three additional PG14 evidence assets are **actual Release
download bytes**, not Actions Artifacts, synthesized files or metadata-only
placeholders. The pg_bigm Release has 16 assets; this row-level contract
independently rehashes **4 of 16**. It also parses the complete original
SHA256SUMS (15 asset entries), comparing every checksum against the recorded
Release digest. It **does not** rehash the other 12 asset payloads. A complete
16/16 Release audit is separate and remains outstanding.

Use only official provenanced GitHub CLI with authenticated Sigstore/TUF
Trusted Root from an independently verified trusted source. Verify TUF
(`gh attestation trusted-root --verify-only`), export current root, confirm
against out-of-band pin. No root substitution, invented root, or
`--insecure-ignore-tlog` override.

Run **only** after collection, with explicit historical opt-in:

```bash
python scripts/distribution_historical_p1_pg14.py \
  --historical-pg-bigm-pg14 \
  --snapshot PRIVATE/SNAPSHOT \
  --trusted-root PRIVATE/tuf-verified-trusted-root.jsonl \
  --catalog-commit 2e850bb5e5a3441edaa887fa5f7c378d22aea4c6
```

Normalizer requires precisely two JSONL outer `{"bundle": ...}` rows, no
duplicate JSON keys, unknown envelope fields, missing DSSE single signature,
extra predicates, mixed signed subjects, oversized payloads or wrong target.
It decodes signed DSSE statements **for preliminary rejection only**; no
unsigned claim is promoted to trust. It emits raw bundle JSON into
temporary files for separate **real** `gh attestation verify --bundle
--custom-trusted-root` calls: one SLSA v1 and one SPDX 2.3.
The wrapper hashes, exact raw normalized JSON hashes and semantic
object hashes are part of the printed receipt. The original signed payload,
signatures, certificate and transparency contents are preserved as-is.

Require both gh calls to return exit 0 **and** check their verified output's
X.509/SAN/OIDC, repo ID, signer full SHA, source digest/ref, original
windows.yml build-config identity/digest, push trigger, exact run/attempt,
subject SHA/name, verified timestamps, distinct predicate and SPDX data.
The receipt indicates `all16AssetsRehashed=false`,
`fleetComplete=false`, `publicationAuthorized=false` even if a whole
single PG14 row passes.

The verifier does not authenticate the independent origin of an operator's
local GET snapshots or the official gh binary. Work must document evidence
provenance and reproduce the result independently; store successful receipts,
original metadata, requested URLs, asset IDs, raw artifact hashes, CLI
origin/version, TUF verification and trusted-root bytes/digest in an
**external, tamper-evident, per-Release/Asset** evidence record. Do not
amend existing GitHub Release/Catalog or report a fixture as real Sigstore.
No root certificate/private key is requested from an independent administrator.

## Historical original SHA256SUMS spelling (Issue #112 GET-only follow-up)

The 2026-10-16 Work run independently fetched the original four pg_bigm
PG14 Release payloads, checked their numeric IDs/size/SHA256 **4/4**,
and compared all **15** original SHA256SUMS entries against Release
metadata. Genuine TUF verification and SLSA v1 / SPDX 2.3 official
`gh attestation verify` each independently returned exit 0.
However, the **merged historical verifier itself returned exit 2** before
CRC/source/gh verification: the untouched original 1,780-byte
`SHA256SUMS.txt` spells each name as `./basename`, which the ordinary
P1 `parse_sums()` intentionally rejects. Its
`invalid/duplicate checksum` diagnostic is **not evidence of a
duplicated digest or filename**.

This profile alone now parses precisely **15** lines of
`<64 lowercase hex SHA256><two spaces>./<safe basename>`. It accepts
exactly one literal `./` and otherwise retains the ordinary
basename constraints. It rejects bare/mixed spelling, nested paths,
`../`, `.//`, `././`, absolute or drive paths, backslashes,
unknown/case-colliding filenames and duplicate normalized entries,
extra/missing lines and non-ASCII/oversized checksums. Only in memory,
it passes the normalized basenames to the **unchanged**
`distribution_release_verify_p1.parse_sums()`, then requires the
exact 15 original Release Asset names. Each digest is still compared to
the original Release metadata. Original signed/raw checksum
**bytes remain untouched**, and the already pinned checksum Asset ID
and full SHA256 must match.

The Work report and private evidence seal are named:
`pgextwin-issue112-pgbigm-pg14-row-audit-20261016.md` and
`pgextwin-issue112-pgbigm-pg14-evidence-seal-20261016.json`.
Original evidence archive:
`pgextwin-issue112-pgbigm-pg14-evidence-20261016.tar.gz`
(SHA256 `559b0c49b59188b4464c347dde5ea96c5b55f512e6c19f2b7b87437281682ca2`;
88-file manifest SHA256 `5e1ead038bebbdad1e81022aa4dac82c65b3792139dc57131a8ef79d403f6ba7`).
Hash seals are tamper-evidence comparisons, not a separate trusted
signature or timestamp.

**After** a protected PR, mandatory CI and safe merge, Work must rerun
the **same original PG14-only row** with the patched verifier against
the untouched 4 Release assets and original SLSA/SPDX bundles.
The earlier independent `gh` success does **not** count as full
historical-verifier row success. Until rerun, rowEvidenceComplete is
false, historical source formally accepted **0/40** and fleet P1
complete **0/70**. No fleet expansion, P2 or public distribution.

## Negative cases and stop conditions

Hostile fixtures cover malformed/duplicate wrappers and predicates,
alternative subjects/PGs, wrong cert repo, workflow/ref/event/buildTrigger,
signer SHA, run/attempt and jobs, absent logs or source Git object,
missing trusted root, unsigned/tampered evidence and wrong byte digests.
The normal P1 regression test suite remains mandatory, as do Catalog
validation and .NET checks. Failed
`plpgsql_check` run `38128142145` attempt 1 is **never eligible**.

The single-row result is **not** an independently completed 70-asset
verification. Until real evidence is obtained and independently reviewed:
historical source formally accepted **0/40**; P1 complete **0/70**;
P1 **BLOCKED**, P2 **NO-GO**, formal distribution **DENY**,
`publicationAuthorized=false`; #75 GO A/GO B/G4/G5 remain NO-GO.

Policy continuity: new completed all-extension offline ZIP is not directly
published. Future CLI constructs a local archive organized as
`packages/pg<major>/<extension>/<version>/...`.
Existing individually published Releases and Website direct-download
links are unchanged.
