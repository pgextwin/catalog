# Issue #112 P1 — GET-only formal Release / offline Sigstore verifier

## Result and scope

This repository adds a **nonpublishing verifier**, not a distribution pipeline.
The read-only adapter checks externally pinned Catalog bytes and release/repo/asset numeric IDs, downloads ORIGINAL formal GitHub Release assets on explicit request, checks SHA256SUMS and actual file bytes, inspects ZIP CRC/PACKAGE-INFO, cross-checks immutable per-major source SHA, and verifies local Sigstore bundles with a separately authenticated trusted root.

**Nothing here is a publishable receipt.** No Workflow Dispatch, reruns, Publisher, signing, Release, tag, website deployment, CLI installer, new schedule or automatic CI download was added. Normal PR CI uses only synthetic fixtures. A passing mock verification is **not** a cryptographic signature. Existing Catalog v2 and Manifest v1 remain unchanged.

## Trust boundary — technical verification, not separate administrator endorsement

**Issue #112 decision (2026-10-16):** A separate administrator approval register, administrator signature, independently registered administrator key fingerprint, or additional person-identity proof is **not** a prerequisite for P1. This changes the approval *policy*; it does not establish that independent approval took place. A candidate Policy/Trusted Root is usable for P1 input when the necessary official-source/commit/ID/hash correspondence and genuine TUF/Sigstore cryptographic checks succeed.

A candidate `pgextwin-p1-readonly-policy/v1` must still pin:

- `catalogCommitSha`: exact immutable 40-hex Catalog commit and `catalogDigests`: raw SHA256 for `index.json` and every `extensions/<name>.json`.
- `repoIds`, `releaseIds`, `assetIds`: complete original GitHub numeric IDs of all 14 repositories, original formal Releases and *every* named asset, including `SHA256SUMS.txt`.
- `signerRepositoryId=1405931353` for `pgextwin/build`, and complete immutable full build-source `trustedSignerShas` allowlist.
- `approvedMajors`, `pgEol`: lifecycle-checked major policy and exact YYYY-MM-DD EOL dates.
- `rootSha256`: locally measured digest of `trusted_root.jsonl` obtained from a **verified, unexpired TUF trust-update chain** through supported GitHub CLI operations.

A Policy loaded from disk is a *candidate*, not a self-authenticating authority. The Python `policy_load` function checks the technical *shape*, not Policy issuer identity or the TUF chain. Verify each source ID/SHA/ref/version from official GitHub immutable refs and original Release resources; use a CLI from verified official provenance. A matching digest supplied by the same untrusted source and ordinary HTTPS GET prove neither TUF authenticity nor an actual Sigstore signature. Do not use an unsigned offline ZIP to bootstrap trust.

Use `gh attestation trusted-root --verify-only` for TUF repository verification and `gh attestation trusted-root > trusted_root.jsonl` for verified root export **after** checking official CLI origin and the full trusted TUF root/update path. The CLI's TUF verification provides cryptographic authenticity, rotation verification, and expiration handling; calculate and pin the exported file's SHA256 only *after* this. If TUF validation, freshness, expected signer identity, certificate or bundle proof fails, **DENY**. An offline Root does not imply current revocation awareness.

## Explicit use (not run as part of this PR)

Read-only online snapshot acquisition with a technically validated candidate Policy:

```sh
python scripts/distribution_release_audit_p1.py --online-get --policy PATH/TO/candidate-policy.json --snapshot PRIVATE/TEMP --trusted-root PATH/TO/tuf-verified-trusted_root.jsonl
```

Subsequently repeat verification with **no online GET**:

```sh
python scripts/distribution_release_audit_p1.py --policy PATH/TO/candidate-policy.json --snapshot PRIVATE/TEMP --trusted-root PATH/TO/tuf-verified-trusted_root.jsonl
```

The second command performs only local file reads and `gh attestation verify` with `--bundle` and `--custom-trusted-root`. It requires the same technically reconciled policy, TUF-validated root and pinned GitHub CLI. The first command performs only allowlisted `gh api`, `gh release download`, and `gh attestation download` reads and local writes under PRIVATE/TEMP. Public Release ZIPs are NEVER replaced by Actions Artifacts.

Both commands emit per-fleet totals (`expected`, `integrityVerified`, `signatureVerified`, `unverified`, `blocked`, `reasons`) and `publicationAuthorized=false`. Exit status is 2 on incomplete fleet. If the CLI, TUF-valid root, upstream pin, verified bundle, Release bytes or API is unavailable, a row is unverified/blocked—not success.

## What is cryptographically bound

- Every RELEASE is stable/nondraft, Release/tag/source commit match and numeric Release ID is externally pinned. Every Asset ID is externally pinned; same-looking replacement assets or filename/path collisions are denied.
- Complete original published asset bytes, sizes and GitHub SHA256 digests, full original `SHA256SUMS.txt`, Catalog ZIP/SPDX/Grype hashes, per-PG source ref/version/full upstream SHA and immutable packaging SHA.
- CRC/size/path/symlink/ZIP-bomb checks (never extraction), `PACKAGE-INFO.json` with signed release-attested mode, exact `pgMajor`, x64, packaging repository+commit, main Promotion run and attempt, immutable builder workflow SHA, SPDX 2.3, Grype report.
- For **each** ZIP: real `gh attestation verify` offline for **both** SLSA v1 and SPDX 2.3, local bundles, TUF-validated pinned root, expected signer workflow AND immutable digest, source ref+digest, OIDC issuer, exact ZIP subject digest, X.509 certified source GitHub repository numeric ID, buildConfig and source SHA, original Promotion invocation URI including `/attempts/N`, and signed predicate.
- A fully verified local result is *still not authorization* to sign or publish an aggregate bundle, nor authority to distribute a Catalog-policy-derived bundle.

Historical caveat: the existing plpgsql_check historical Promotion has a known failure conclusion after signed builds; this P1 fail-closed adapter requires successful formal Promotion by default and **does not silently grandfather exceptions**. A distinct explicitly authorized, technically validated historical exception would be required before treating it as complete. Mixing job attempts is never permitted.

## Dynamic compatibility

No new 14-extension or PG14–18 hard-coded operational matrix is introduced. Supported rows derive from pinned Catalog, immutable extension configuration and externally approved major policy. PG14 supported through **2026-11-12 UTC**, then historical **2026-11-13 UTC**. PG19 RC1 on **2026-10-15** is not GA and has **no approved binary**; the planned **2026-11-19** GA is not an authorization. Synthetic 15-extension and PG19 tests do not assert any actual PG19 formal Release exists.

## Acceptance / outstanding before P2

P0 already accepted: Catalog #60, main e4f2024250d21b26df07063cb62e070e1a4053cd.
All current 14 latest formal Release metadata listed five ZIP per extension; only **70/70 metadata digests** were previously matched. This Chat environment cannot fetch ZIP binary bytes (external DNS/network unavailable); P1 independent real ZIP SHA256 **0/70**, genuine new Sigstore verification **0/70**. Do not carry forward historical canary results as P1 proof.

Required follow-up: technically reconcile the candidate Policy, and cryptographically validate the TUF Trusted Root; execute bounded GET-only live snapshot+offline verification with resources available; review 70/70 evidence and any blocked historical run or missing attestation; perform byte-level extra adversarial cases. **P2 local bundle is NO-GO** until source, bytes, attestations, environment and root all meet independent gates. GO A/GO B/G4/G5 remain NO-GO; formal distribution remains DENY.

## P1 technical restart runbook (GET-only; no independent administrator approval evidence)

1. **Confirm tooling and record provenance.** In a trusted online environment, obtain GitHub CLI from the official release or authenticated package source; establish distribution signature/provenance, its on-disk executable path and SHA256, `gh --version`, `gh auth status`, `python --version`, available disk, and network capability. Verify `gh attestation trusted-root --help`, `gh attestation download --help`, and `gh attestation verify --help` expose this P1 adapter's flags. Record these values in local private evidence. The present PR does not install anything.
2. **Cryptographically verify the TUF trust root online.** Run `gh attestation trusted-root --verify-only` (exit 0 required), followed by `gh attestation trusted-root > tuf-verified-trusted_root.jsonl` (exit 0 required) using the genuine official GitHub CLI and its official/embedded initial TUF trust anchor. Confirm a valid, unexpired threshold-signed TUF metadata update chain (root rotations plus timestamp, snapshot and targets). A custom mirror requires securely authenticated initial `root.json` and both `--tuf-url` and `--tuf-root`; anonymous HTTP downloads and same-origin checksums are **not** substitutes. If CLI verification/metadata freshness cannot be established, STOP. Record TUF source, initial root identity, verified update time and expiry evidence. Compute actual SHA256 of exported root and assign `rootSha256` in candidate Policy. Recreate and revalidate on root rotation; offline results cannot claim present revocation status.
3. **Construct and cross-check the candidate Policy.** Check current `pgextwin/catalog` protected `main` SHA and immutable ancestry; fetch exact `index.json` and 14 Catalog records **at this SHA**, and hash their raw bytes. Reconcile each current extension's official GitHub repository numeric ID, latest stable nondraft original Release ID/tag/target SHA, resolved tag commit, protected `main` ancestry and *every* Release asset numeric ID including checksum/SPDX/Grype files. Require full version/ref/upstream commit SHA for each major against original immutable extension config, Catalog digests and builder's full signer SHA; verify official `pgextwin/build` repo ID is 1405931353. Only allow verified eligible PG majors/EOL (PG19 RC is not GA). Record where each field came from and the local candidate Policy SHA256. This is technical consistency/identity evidence, **not** an administrator approval artifact or Sigstore attestation.
4. **Keep roots and pins outside the snapshot.** Store `candidate-policy.json` and `tuf-verified-trusted_root.jsonl` separately from downloaded data/any offline archive. Check `rootSha256` against the **verified** Root file; ensure `policy_load` accepts all mandatory fields and that the official identities/hashes corroborate them. Use independent direct byte-hash measurements, not copied Release metadata checksums as proof of downloaded bytes.
5. **Run existing nonpublishing audits.** Execute the two commands in the preceding section, first with explicit `--online-get` and then without it on the same private snapshot. Online calls are restricted to allowlisted GET/`gh release download`/`gh attestation download`. Offline verification uses locally downloaded genuine bundles, the TUF-validated pinned Root, both `gh attestation verify` predicate types (SLSA v1/SPDX 2.3), signer workflow+SHA, certified numeric repository ID, PG major, package/source SHA, exact Promotion run **and attempt**, and ZIP subject SHA256. Never replace Release ZIPs with CI artifacts or use a mock result as a proof.
6. **Capture decisions and stop safely.** Record Catalog/build commit, CLI binary path/hash/version, TUF validity and root digest, candidate Policy digest/IDs, **original** Release bytes and each SHA256SUMS/SPDX/Grype match, SLSA+SPDX verified result by PG-major ZIP, and the P1 JSON counters. Require `expected=70`, `integrityVerified=70`, `signatureVerified=70`, `complete=true` before declaring full 70-ZIP technical acceptance. If original bytes, CLI, Root/TUF, API, signed proof, correct run attempt or successful historical Promotion cannot be established, report the row BLOCKED. The known plpgsql_check Promotion failure is **not waived**. An environment unable to perform real downloads/cryptographic verification must report **0/70 real evidence in that environment**, even after all synthetic tests pass.

**Invariant:** `publicationAuthorized=false`, P2 NO-GO, formal distribution DENY and Issue #75 GO A/GO B/G4/G5 blocked regardless of P1 preflight status. Do not issue Workflow Dispatch, signing, Tag, Release, Publisher, installer, or an aggregate bundle.

Reference documentation: https://cli.github.com/manual/gh_attestation_trusted-root , https://cli.github.com/manual/gh_attestation_verify , https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/verify-attestations-offline .

## CLI-first distribution policy

There is **no direct publication of a new prebuilt fleet-wide offline ZIP**. Later, the user-facing CLI alone will generate the offline archive **locally**, arranged by PostgreSQL major (`packages/pg<major>/<extension>/<version>/...`), while the shared engine supports both online access and that locally generated archive as offline input. This P1 PR does not touch existing individual published Release ZIPs, existing Website direct-download links, synthetic Bundle fixture boundaries or any publisher.
