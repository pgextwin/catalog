# Issue #112 P1 — GET-only formal Release / offline Sigstore verifier

## Result and scope

This repository adds a **nonpublishing verifier**, not a distribution pipeline.
The read-only adapter checks externally pinned Catalog bytes and release/repo/asset numeric IDs, downloads ORIGINAL formal GitHub Release assets on explicit request, checks SHA256SUMS and actual file bytes, inspects ZIP CRC/PACKAGE-INFO, cross-checks immutable per-major source SHA, and verifies local Sigstore bundles with a separately authenticated trusted root.

**Nothing here is a publishable receipt.** No Workflow Dispatch, reruns, Publisher, signing, Release, tag, website deployment, CLI installer, new schedule or automatic CI download was added. Normal PR CI uses only synthetic fixtures. A passing mock verification is **not** a cryptographic signature. Existing Catalog v2 and Manifest v1 remain unchanged.

## Trust boundary and operator-authenticated inputs

An external trusted-policy file must be obtained/authenticated **independently from the snapshot and release assets**. Its schemaVersion is `pgextwin-p1-readonly-policy/v1`. It MUST pin:

- `catalogCommitSha` as a full immutable 40-hex commit ID and `catalogDigests` exact raw SHA256 of `index.json` and every `extensions/<name>.json` blob.
- `repoIds` numeric GitHub repository IDs for all expected extensions; `releaseIds` immutable numeric published Release IDs; `assetIds` numeric IDs keyed by *every* original named Release asset, including SHA256SUMS.
- `signerRepositoryId` = 1405931353 for pgextwin/build and `trustedSignerShas` allowlisted full immutable reusable builder source commit SHAs.
- `approvedMajors` dynamic list (for example 14 through 18 for currently approved PG), `pgEol` exact YYYY-MM-DD by PG major.
- `rootSha256`, independently authenticated digest of an external `trusted_root.jsonl` fetched/validated according to GitHub/Sigstore TUF trust policy.

**DO NOT** generate the trusted policy from the same unsigned offline bundle, or blindly accept a policy whose origin/authorization is unknown. The code checks policy consistency, not who approved the policy. A malicious self-authorized policy is not proof. Missing/rotated/untrusted root means DENY; no silently degraded verification.

Offline trusted material can be obtained in an online trusted environment per GitHub guidance: `gh attestation trusted-root > trusted_root.jsonl`, authenticate it out of band, and pin its real digest. Roots can rotate; offline verification does not claim current revocation awareness. Do not treat bundled trusted-root content as an independent anchor.

## Explicit use (not run as part of this PR)

Read-only online snapshot acquisition using a separately authenticated policy:

```sh
python scripts/distribution_release_audit_p1.py --online-get --policy PATH/TO/authenticated-policy.json --snapshot PRIVATE/TEMP --trusted-root PATH/TO/authenticated-trusted_root.jsonl
```

Subsequently repeat verification with **no online GET**:

```sh
python scripts/distribution_release_audit_p1.py --policy PATH/TO/authenticated-policy.json --snapshot PRIVATE/TEMP --trusted-root PATH/TO/authenticated-trusted_root.jsonl
```

The second command performs only local file reads and `gh attestation verify` with `--bundle` and `--custom-trusted-root`. It requires the same independently authenticated policy and GitHub CLI installed. The first command performs only allowlisted `gh api`, `gh release download`, and `gh attestation download` reads and local writes under PRIVATE/TEMP. Public Release ZIPs are NEVER replaced by Actions Artifacts.

Both commands emit per-fleet totals (`expected`, `integrityVerified`, `signatureVerified`, `unverified`, `blocked`, `reasons`) and `publicationAuthorized=false`. Exit status is 2 on incomplete fleet. If the CLI, authenticated root, upstream pin, verified bundle, Release bytes or API is unavailable, a row is unverified/blocked—not success.

## What is cryptographically bound

- Every RELEASE is stable/nondraft, Release/tag/source commit match and numeric Release ID is externally pinned. Every Asset ID is externally pinned; same-looking replacement assets or filename/path collisions are denied.
- Complete original published asset bytes, sizes and GitHub SHA256 digests, full original `SHA256SUMS.txt`, Catalog ZIP/SPDX/Grype hashes, per-PG source ref/version/full upstream SHA and immutable packaging SHA.
- CRC/size/path/symlink/ZIP-bomb checks (never extraction), `PACKAGE-INFO.json` with signed release-attested mode, exact `pgMajor`, x64, packaging repository+commit, main Promotion run and attempt, immutable builder workflow SHA, SPDX 2.3, Grype report.
- For **each** ZIP: real `gh attestation verify` offline for **both** SLSA v1 and SPDX 2.3, local bundles, authenticated external trusted root, expected signer workflow AND immutable digest, source ref+digest, OIDC issuer, exact ZIP subject digest, X.509 certified source GitHub repository numeric ID, buildConfig and source SHA, original Promotion invocation URI including `/attempts/N`, and signed predicate.
- A fully verified local result is *still not authorization* to sign or publish an aggregate bundle, nor proof that the independently authenticated Catalog-policy distribution mechanism has been accepted.

Historical caveat: the existing plpgsql_check historical Promotion has a known failure conclusion after signed builds; this P1 fail-closed adapter requires successful formal Promotion by default and **does not silently grandfather exceptions**. Distinct independently approved explicit historical waiver/policy and authentic verification would be needed before treating it as complete. Mixing job attempts is never permitted.

## Dynamic compatibility

No new 14-extension or PG14–18 hard-coded operational matrix is introduced. Supported rows derive from pinned Catalog, immutable extension configuration and externally approved major policy. PG14 supported through **2026-11-12 UTC**, then historical **2026-11-13 UTC**. PG19 RC1 on **2026-10-15** is not GA and has **no approved binary**; the planned **2026-11-19** GA is not an authorization. Synthetic 15-extension and PG19 tests do not assert any actual PG19 formal Release exists.

## Acceptance / outstanding before P2

P0 already accepted: Catalog #60, main e4f2024250d21b26df07063cb62e070e1a4053cd.
All current 14 latest formal Release metadata listed five ZIP per extension; only **70/70 metadata digests** were previously matched. This Chat environment cannot fetch ZIP binary bytes (external DNS/network unavailable); P1 independent real ZIP SHA256 **0/70**, genuine new Sigstore verification **0/70**. Do not carry forward historical canary results as P1 proof.

Required follow-up: independently authenticate the full policy and trusted root; execute bounded GET-only live snapshot+offline verification with resources available; review 70/70 evidence and any blocked historical run or missing attestation; perform byte-level extra adversarial cases. **P2 local bundle is NO-GO** until source, bytes, attestations, environment and root all meet independent gates. GO A/GO B/G4/G5 remain NO-GO; formal distribution remains DENY.
