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
