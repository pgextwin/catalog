# pgextwin CLI — Issue #112 (nonpublishing, PR-2)

.NET 10 local-only `list/search` and explicit **single-asset** GET-only `download`.
This is not an installer, a signer, a fleet/bundle generator, a Publisher or a trusted
Sigstore verification engine. The Python P0 Manifest v1 builder/Schema and P1
Release/Sigstore verification remain the authoritative independent acceptance path.

```bash
dotnet build dotnet/PgExtWin.slnx --configuration Release
dotnet run --project dotnet/tests/PgExtWin.Contract.Tests --configuration Release --no-build
dotnet run --project dotnet/src/PgExtWin.Cli -- list --catalog-dir . --pg 18
dotnet run --project dotnet/src/PgExtWin.Cli -- search cron --catalog-dir .
```

A **separately administrator-authenticated** P1 policy and SHA256 are mandatory for
a real download. The hash must arrive by an independently authenticated channel,
not merely by copy/pasting it from the same Catalog, GitHub API or snapshot.
The output directory must already exist, be link-free and not contain a colliding
filename. This command is NOT executed in CI and does not authenticate signatures:

```bash
dotnet run --project dotnet/src/PgExtWin.Cli -- download pg_cron --pg 18 \
  --catalog-dir /trusted/catalog-snapshot --policy /independently/approved/policy.json \
  --policy-sha256 OUT_OF_BAND_64_HEX_DIGEST --output /private/staging
```

It checks all pinned Catalog raw SHA256s, numeric Repo/Release/asset ID inventories,
release/tag/asset metadata and 1 original ZIP's streamed actual bytes with a 64MiB
cap, and writes to a collision-free private staging filename before no-overwrite
rename. Explicit HTTPS GET only; auto-redirect disabled, bounded manually to
approved GitHub asset transport hosts. All evidence stays **INTEGRITY_ONLY**:
`SIGNATURE_VERIFIED=0` / `PUBLISH=DENY`, including when the digest matches.

Tests use synthetic P1 policy, in-memory ZIP and a fake HTTP transport with
no external network/credentials. No real 70 ZIP rehash or Sigstore run has occurred.
P1 BLOCKED, P2 NO-GO, formal publication DENY, `publicationAuthorized=false`.

## PR-3: synthetic-only offline ZIP fixture laboratory

`PgExtWin.Bundles.SyntheticBundle` accepts only in-memory synthetic ZIPs with an exact
`SYNTHETIC-FIXTURE.txt` proof marker and rejects real `PACKAGE-INFO.json`.
It never touches the live `download` command, filesystem, network, GitHub Releases,
Sigstore or P1 verifier. The outer test ZIP is deterministic and has
`fixture-manifest.json` (NOT `manifest.json`), a mandatory visible
`SYNTHETIC-DO-NOT-DISTRIBUTE.txt` banner and bytes under
`packages/pg<major>/<extension>/<version>/<filename>.zip`.
The manifest has a distinct `pgextwin-synthetic-bundle-fixture/v1` identity,
`UNVERIFIED`, `publicationAuthorized=false` and `outerArchiveSigned=false`.
Its canonical JSON and deterministic snapshot hash reuse the PR-1 P0-style
`StrictJson` implementation; this is NOT P0 Manifest v1 schema validation
and not P1 SLSA/SPDX cryptographic signature validation.

The fixture library and hostile tests are compiled/run in the existing
App15368 `validate` job with no new workflow and no Actions Artifact.
This library is deliberately NOT exposed as a CLI command or production Bundle
creator. No real Release ZIP can be accepted by this fixture harness under
its explicit synthetic marker contract. Real fleet ZIP work remains blocked
by the independent P1 policy/Trusted Root and 70/70 genuine verification gates.

## PR-4: independently approved P1 report handoff (not a signature verdict)

`PgExtWin.Trust.P1Handoff` is a **pure, offline, read-only integration
boundary**, not a Sigstore verifier or P1 execution engine. Its input is a
detached ECDSA-P256/SHA256-signature-bearing *report claim* whose public
key, P1 verifier script SHA256, authenticated P1 policy SHA256 and Trusted
Root SHA256 are all supplied **independently** of the report (and NOT read
from any archive or GitHub API response). The canonical UTF-8 payload
identifies exactly one original package ZIP through Repo/Release/Asset
numeric IDs, PG major, Catalog full commit and ZIP hash, and asserts full
fleet counts and nonpublishing-only decision. The independent authority
must review all original P1 evidence and signer identity before issuing
its signed handoff; that external act is NOT performed here.

For all inputs, including correctly signed synthetic reports asserting
`signatureVerified=70`, this API returns only
`P1_REPORT_AUTHENTICATED_ONLY / UNVERIFIED` with
`SignatureVerified=false, PublicationAuthorized=false, MayInstall=false,
MayBuildRealBundle=false`. **A signature authenticates the source of the
assertion, not the truth of the underlying Sigstore proof.** Production
cryptographic acceptance still requires re-running existing P1
`distribution_release_audit_p1.py` with independently authenticated
policy/root and original bytes, then separately validating its run evidence.
The PR intentionally does not create a CLI command or trust-granting
method, run Python or `gh attestation verify`, fetch Release ZIPs, create
Bundle ZIPs, or change `PkgExtWin.Bundles`.

CI uses an ephemeral test-only ECDSA key in memory to exercise signature,
pin, JSON, identity, replay, counts and publication-denial cases.
No genuine P1 policy/Root approval, 70/70 audit, real signing or public
release is claimed. P1 BLOCKED; P2 NO-GO; formal distribution DENY.

## Windows self-contained CLI publish-readiness smoke (nonpublishing)

See [public CLI release plan](../docs/cli-public-release-plan.md). The PR-only
`cli-windows-package-smoke` job produces a **private, ephemeral**
`win-x64` self-contained single-file `pgextwin.exe`, prints its SHA256/size,
runs actual Windows help/list/search (PG18) and DENY/exit-2 negative paths.
It does not upload an Actions Artifact or create any tag, signed binary,
Release, public download, installer or bundle.

This is compile/runtime evidence only. No trusted online/offline `verify`,
bundle creation, `install`, source Sigstore acceptance or public CLI signing is
implied. Existing `PUBLISH=DENY` and P1 65/70 + five DENY remain unchanged.

## Machine-readable local Catalog output

The CLI preview version is `0.1.0-preview.1` (`pgextwin --version`).
`list` and `search` accept `--format json` in addition to their default
text format:

```powershell
pgextwin.exe list --catalog-dir C:\\path\\to\\catalog --pg 18 --format json
pgextwin.exe search cron --catalog-dir C:\\path\\to\\catalog --format json
```

JSON uses `pgextwin-cli-local-catalog/v1` and carries
`source=LOCAL_UNAUTHENTICATED`, `trust=UNVERIFIED`, and
`catalogAuthenticated=false`, `signatureVerified=false`,
`publicationAuthorized=false`, `distributionAuthorized=false`.
Its rows are local Catalog metadata **only**, not an authenticated manifest
or verified Release claim. `download --format json` is rejected, and unknown
formats fail closed with exit 2. This output is not a trust upgrade.

## R2a: CLI authentication of an externally signed P1 *report claim*

`pgextwin verify-report` authenticates a detached, canonical ECDSA-P256/SHA256
P1 report using an **independently approved** SHA256 digest of the public key,
an independently pinned P1 policy, Trusted Root digest, and P1 verifier digest.
It checks the Catalog's raw digests and the **exact** PG-major, repository ID,
release ID, asset ID and original ZIP digest against the signed report. It runs
offline, reads bounded local files, and never changes any filesystem content.

```powershell
pgextwin.exe verify-report pg_cron --pg 18 --catalog-dir C:\\approved\\catalog `
  --policy C:\\approved\\policy.json --policy-sha256 OUT_OF_BAND_POLICY_SHA256 `
  --trusted-root-sha256 OUT_OF_BAND_ROOT_SHA256 `
  --p1-verifier-sha256 OUT_OF_BAND_VERIFIER_SHA256 `
  --report C:\\approved\\p1-report.json --signature C:\\approved\\p1-report.sig `
  --authority-key C:\\approved\\authority.pem --authority-key-sha256 OUT_OF_BAND_KEY_SHA256
```

The output is `P1_REPORT_AUTHENTICATED_ONLY` and explicitly
`TRUST=UNVERIFIED SIGSTORE_SIGNATURE_VERIFIED=false ORIGINAL_BYTES_VERIFIED=false PUBLISH=DENY`.
The report's issuer is authenticated, but the CLI **does not independently
check a genuine Sigstore SLSA/SPDX proof, trusted-root contents, original Release
bytes, revocation status, or whether an independently approved P1 auditor really
produced the report**. Status 0 means *report signature and pins matched*, never
release or distribution verification. R2 genuine online/offline Sigstore
verification, R3 bundles and R7 publication remain gated.

Only synthetic ephemeral signing keys and synthetic files are used in CI.
The CLI public binary and any real extension Release are not published.

## v0.2.0 — fetch all original ZIPs for one or five PostgreSQL majors

The `download-all` command reuses the **previously validated** Catalog v2, P1 policy
pins, and single-ZIP bounded, GET-only downloader. Use `--pg 18` to fetch 14 ZIPs,
or `--pg all` to fetch the full 70 ZIPs (PG14–18). Examples:

```powershell
New-Item -ItemType Directory -Force C:\\pgextwin-downloads
.\\pgextwin.exe download-all --pg 18 --catalog-dir C:\\approved\\catalog \`
  --policy C:\\approved\\policy.json --policy-sha256 OUT_OF_BAND_APPROVED_HEX \`
  --output C:\\pgextwin-downloads
```

Each ZIP is saved in `pg<major>/` under a new `pgextwin-pg<major>` directory;
`--pg all` creates `pgextwin-pg14-18/pg14/` through `pg18/`. The directory
is exposed only after all selected original bytes have passed their SHA256 and
numeric GitHub Release identity checks. If one fails, staging is removed and
existing output is never overwritten. `DOWNLOAD-INFO.json` keeps the complete
package inventory and explicitly sets all signer/provenance/install authority
flags to **false**; a digest match is `INTEGRITY_ONLY`, not signature verification.

This is bulk retrieval of individually published ZIPs, **not** a signed enclosing
archive or an installer. It requires a separately approved current P1 policy
and SHA256; where independent validation is unavailable, it rejects rather than
silently downgrading the trust claim. See [v0.2 guide](../docs/cli-v0.2-batch-download.md).

## v0.2.1 one-command original ZIP retrieval

From the directory where you want a new `pgextwin-pg14-18` folder:

```powershell
.\\pgextwin.exe download-all --pg all
```

No separately downloaded Catalog, P1 candidate policy file, SHA or output path is needed.
The signed CLI binary **embeds** the historical P1 candidate policy's original SHA256
and exact immutable source commits. It fetches only the fixed policy and the 15
original Catalog v2 files over HTTPS, verifies every original byte against the
policy, and then reuses the existing strict numeric-ID/SHA256 GitHub Release ZIP
downloader for all 70 files. Partial output is discarded if any asset fails;
all original ZIPs remain `INTEGRITY_ONLY`, not genuinely signature-verified.

The fixed policy is a **candidate PIN SET**, not an assertion that 70 historic
P1 authentic signed-release acceptances are complete. The one-line mode is a
frozen 2026-10-17 Catalog/release snapshot, not an automatically updated latest
extensions feed. Failures against mutated or replaced historical assets are
intentional and do not silently select newer packages or waive safety gates.

To use a different independently approved snapshot or an explicit destination,
keep using the existing full set of `--catalog-dir`, `--policy`,
`--policy-sha256` and `--output` arguments.
