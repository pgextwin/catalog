# Issue #112 — historical source and anonymous GET-only bridge

Status: **nonpublishing transport implementation only; P1 0/70 remains BLOCKED**.
This does not replace `distribution_release_audit_p1.py` or
`distribution_release_verify_p1.py`, and never calls Publisher.

## Verified GitHub metadata (2026-10-16)

The exact original Release `target_commitish` versions of
`config/extension.json` have upstream ref/version but omit the full
`upstream.commit` for every PG14–18 row (40 rows total).

| Extension | Fixed Release ID | Original packaging target SHA |
|---|---:|---|
| pg_bigm | 408449466 | cfbb52f8caf41b2c393a1a34f6011157979af2bb |
| pg_cron | 408447762 | c1e7cf92b86e7dd06c73549ba6e39ee6b272b191 |
| pg_hint_plan | 408447843 | 3a3625ee23efa763f06c5cf403a0f44b512e3038 |
| pg_ivm | 408456115 | f186e7ad5a95a08db8e086a0bf7af0abd3de3e58 |
| pg_qualstats | 408453847 | 30792eb708829c3336cf608d7f55bdbf4b60f42f |
| pg_repack | 408452263 | b9912670576e643ac2c04bb590c412500088d725 |
| pgaudit | 408453283 | 4a6dcb3bc8fbffa6ea180a2a156f335ff0081997 |
| set_user | 408453245 | 6599fa167fd29a24839b21e732887208395de82f |

This table is public GitHub **metadata**, not a byte-level or cryptographic
acceptance. Every individual ZIP has its own Release Asset ID, size and
digest, which must be reconciled with the external Policy before any GET.

## Why a historical SHA may be recoverable but is not yet accepted

At the original build's immutable signer workflow,
`build-extension-attested.yml` checked out
`matrix.upstreamCommit || matrix.upstreamRef` for each major.
`finalize-package.ps1` then resolved the actual upstream checkout
`git rev-parse HEAD` when `UpstreamCommit` was not passed, enforced a
full 40-character commit SHA, and embedded it in ZIP `PACKAGE-INFO.json`.

**Required historical exception proof order (future narrowly scoped
verifier change, not implemented here):**

1. Pin original Catalog/packaging, numeric Repo/Release/Asset ID and
   externally reconciled original ZIP SHA256, check actual ZIP bytes.
2. Independently run existing offline GitHub CLI verification using the
   genuine TUF-validated Root and **both** SLSA v1 + SPDX 2.3
   attestations. Enforce signer workflow SHA, certificate/OIDC, source
   repository numeric identity, exact main Promotion **run and attempt**
   and success; historical plpgsql_check failed Promotion must not be waived.
3. Only *after* successful genuine proof, parse safe, CRC-checked
   `PACKAGE-INFO.json` and bind its `upstream.commit` to the original
   ZIP subject SHA256, immutable Release/Asset identity and upstream
   ref/version in the original config. Confirm its full SHA object exists
   in the upstream Git repository and corroborate original checkout/CI
   evidence and tag's historical relationship; current mutable tag state
   alone is **not** sufficient.
4. Store any historical acceptance as separate immutable external
   per-asset evidence, not a mutation to Release/config/Catalog.
   Continue requiring full SHA for all ordinary new builds.
5. Any unverified, absent, contradictory or irreproducible evidence
   remains row-level **BLOCKED**.

The presently accepted `immutable_source()` requirement is unchanged.
There is no source-pin waiver or auto-inference from PACKAGE-INFO.

## Anonymous GET transport pilot (opt-in; one original ZIP)

`scripts/distribution_p1_anonymous_get.py` only retrieves a single
original ZIP and the public associated Sigstore bundles using GitHub's
anonymous REST GET endpoints. CLI requires caller-supplied **independently
reconciled** numeric Repo/Release/Asset identities, original asset SHA256
and byte size, exact Release packaging SHA and Release tag. The output is
always `UNVERIFIED` and `publicationAuthorized=false`, regardless
of data returned by GitHub. The resulting JSONL bundle is an **untrusted
transport representation** until the existing genuine `gh attestation
verify --bundle --custom-trusted-root` succeeds.

Example (use exact pins from your externally reviewed P1 Policy; directory
must already exist and contain no files with the chosen names):

```text
python scripts/distribution_p1_anonymous_get.py \
  --repo RECONCILED_EXTENSION \
  --repo-id RECONCILED_NUMERIC_REPO_ID \
  --release-id RECONCILED_NUMERIC_RELEASE_ID \
  --asset-id RECONCILED_NUMERIC_ASSET_ID \
  --asset-sha256 RECONCILED_ZIP_SHA256_64_HEX \
  --asset-size RECONCILED_ZIP_BYTE_SIZE \
  --target-sha RECONCILED_PACKAGING_COMMIT_40_HEX \
  --tag RECONCILED_RELEASE_TAG \
  --output-dir EXISTING_PRIVATE_STAGING_DIRECTORY
```

- HTTPS GET only; fixed API path shapes; no Auth header, token, credential
  prompt, `gh auth`, GitHub write method or CI Dispatch.
- Exact numeric identity/ZIP filename/tag/packaging SHA plus externally
  supplied digest/size; actual streamed-byte size and SHA256 validation.
- No redirect is automatically followed: bounded hops and strict host
  allowlisting. Unknown hosts, network error, rate limit, 401/403/429,
  partial/short/oversized response and path/overwrite hazards fail closed.
- GitHub public attestation API may return inline bundles or references
  to public blob storage. Both are **DATA**, never self-attesting trust.
- **Unauthenticated REST primary rate limit is ordinarily 60 requests
  per hour per originating IP.** This one-ZIP opt-in pilot is not a
  claim that all 70 packages can be fetched at once. Respect rate-limit
  response headers, do not rotate identities to evade limits, and do
  not treat incomplete snapshots as complete. Some GitHub asset and
  storage redirect hosts may vary: unexpected new hosts must be reviewed,
  not automatically accepted.

Current Chat runtime external DNS failed; no real Release ZIP/Attestation
GET or cryptographic verification was performed. Unit tests use only
synthetic mocked HTTP. Remaining full-P1 acceptance gates are **0/70**,
P2 NO-GO, formal distribution DENY, `publicationAuthorized=false`.
No new prebuilt fleet-wide ZIP is published; future CLI creates local
PG-major-organized offline ZIPs. Existing individual Release ZIPs and
Website links are unchanged.
