# Issue #112 — pgsql-http Windows x64 candidate (nonpublishing)

**Status: CANDIDATE_ONLY / PUBLIC_GET_DENY / MIRROR_DENY / RELEASE_DENY.** This record adds one previously unlisted extension to the independent Windows source landscape; **no public pgextwin CLI GET has been enabled**.

## Primary-source discovery, 2026-11-11 JST

The PostgreSQL Windows binary publisher [Postgres OnLine Journal](https://www.postgresonline.com/article_pfriendly/371.html) lists separate Windows x64 ZIPs for EDB PostgreSQL 14–18. The [upstream source repository](https://github.com/pramsey/pgsql-http) is a different party from that Windows binary publisher. The upstream [latest source release v1.7.2](https://github.com/pramsey/pgsql-http/releases/tag/v1.7.2) does **not** establish that the binary publisher built its ZIPs from that source tag.

| PostgreSQL major | Publisher's stated extension version | Publisher original ZIP URL | Cryptographic original-byte verification |
| --- | --- | --- | --- |
| 14 | 1.5.0 | https://www.postgresonline.com/downloads/pg14http_w64.zip | NOT VERIFIED |
| 15 | 1.6.1 | https://www.postgresonline.com/downloads/pg15http_w64.zip | NOT VERIFIED |
| 16 | 1.6.1 | https://www.postgresonline.com/downloads/pg16http_w64.zip | NOT VERIFIED |
| 17 | 1.7.1 | https://www.postgresonline.com/downloads/pg17http_w64.zip | NOT VERIFIED |
| 18 | 1.7.1 | https://www.postgresonline.com/downloads/pg18http_w64.zip | NOT VERIFIED |

These are **publisher-reported download locations, not independent observed SHA256/size receipts**. Do not assert that all five transfers, ZIP structure, loader resolution, `CREATE EXTENSION`, or the versions inside each binary have been verified. A local attempt to retrieve the PG18 ZIP for independent hashing was unsuccessful; its hash/size remain unknown rather than invented.

The source project's GitHub repository currently declares MIT licensing. The Windows article states the binary packages are built for EDB Windows PostgreSQL and may rely on libcurl, PCRE and EDB's `ssleasy.dll`. This creates separate unresolved dependency and license/NOTICE obligations, especially without a verified installation and binary inventory.

## Source admission boundary

Existing pgextwin `download-all --source external` requires immutable GitHub Release identity, exact independent original bytes, protected Catalog current HEAD, source-specific signed Build issuer admission, independent Sigstore verification, live expiry and atomic local-only GET. **These external web-hosted ZIPs do not have GitHub Release repository/release/asset IDs.** Do not fabricate such IDs or route through the GitHub-only transport. The current signed-cohort issuer and CLI are deliberately unchanged.

Follow-up, only if independently justified: inspect and hash the five original ZIPs via the publisher origin; verify source revisions, build history, package contents, exact PG ABI, loader dependencies, licenses and notices; then design and review a separate strictly pinned HTTPS transport and authenticated source-specific admission before any public GET. Preserve all current fail-closed behavior and independent Publisher/Website gates.

**Current deliverable:** research metadata added to `landscape/extensions/http.json` and the 25-entry landscape index. This candidate is not added to distribution `index.json`, a signed `qualified_cohort`, or any published release. No original ZIP, third-party source, license file or binary is mirrored.


## Exact-origin original-byte observation pilot (2026-11-11; NONPUBLISHING)

New `scripts/issue112_http_original_receipts.py` and PR-only matrix
`.github/workflows/issue112-http-original-receipts.yml` attempt actual
original publisher HTTPS ZIP GET for **PG14, 15, 16, 17 and 18** without any
mirror, cross-origin redirect, signed feed, release asset identity fabrication,
artifact upload, user-facing CLI invocation or Publisher call.

For each responding original the inspector **observes**, but does not
authenticate, a complete streamed byte count/SHA256 and bounded original ZIP
structure, member CRC, safe paths, exactly one AMD64 `http.dll`,
`http.control`, and candidate rights-file names. These are **untrusted
initial receipts**, not pre-established SHA pins, rights/source-version
acceptance, upstream-producer signature, Windows runtime closure or a
cryptographic source-to-exact-binary attestation. The ZIP stays temporary and
is deleted. The workflow also executes adversarial offline tests. A failing
remote transfer or malformed archive remains **FAILURE** and must never be
treated as successful GET verification.

All versions here are **Windows publisher-advertised**, NOT established as
upstream v1.7.2. No actual original hash should be entered in a promoted
Catalog pin until separately reviewed and reproduced. The original earlier
PG18 local GET failure is preserved as earlier evidence, not silently
overwritten.

**Admission boundary unchanged:** CANDIDATE_ONLY / PUBLIC_GET_DENY /
MIRROR_DENY / RELEASE_DENY. Independent publisher identity, legal/NOTICE
closure, exact source revision/build provenance, Windows loader/SQL acceptance,
new strict external-HTTPS source-specific signed issuer design and formal
authorization all remain open.
