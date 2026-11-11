# Issue #112 — pgsql-http Windows x64 candidate (nonpublishing)

**Status: CANDIDATE_ONLY / PUBLIC_GET_DENY / MIRROR_DENY / RELEASE_DENY.** This record adds one previously unlisted extension to the independent Windows source landscape; **no public pgextwin CLI GET has been enabled**.

## Primary-source discovery, 2026-11-11 JST

The PostgreSQL Windows binary publisher [Postgres OnLine Journal](https://www.postgresonline.com/article_pfriendly/371.html) lists separate Windows x64 ZIPs for EDB PostgreSQL 14–18. The [upstream source repository](https://github.com/pramsey/pgsql-http) is a different party from that Windows binary publisher. The upstream [latest source release v1.7.2](https://github.com/pramsey/pgsql-http/releases/tag/v1.7.2) does **not** establish that the binary publisher built its ZIPs from that source tag.

| PostgreSQL major | Publisher's stated extension version | Original observed bytes | Original observed SHA256 (research only) |
| --- | --- | ---: | --- |
| 14 | 1.5.0 | 1,375,832 | `e2b4fe130f145875710e61d43f055e7fb6642f61eb65051457d7e49d6e6f9a96` |
| 15 | 1.6.1 | 1,371,729 | `15202e92b4170e4f81b7369496789bdcd7f870cff23aed17f10403a37d342685` |
| 16 | 1.6.1 | 800,277 | `946429cc25d3b4235f276777d01ff89d2161d898a5dd4ce2c46305dbdb98edb8` |
| 17 | 1.7.1 | 3,640,379 | `f4fad2ca74e172fdb77d53f21ed63f27d08b271bfbe3084572f703171c67566a` |
| 18 | 1.7.1 | 7,043,584 | `7904f4498c9c011f7a433aed3d735ce38100b4564248e91654e81f9eebc24964` |

Cryptographic original-byte verification: the initial response hashes above are observed; producer authenticity, source provenance and public admission remain **NOT VERIFIED**.

Exact publisher original URLs:
- https://www.postgresonline.com/downloads/pg14http_w64.zip
- https://www.postgresonline.com/downloads/pg15http_w64.zip
- https://www.postgresonline.com/downloads/pg16http_w64.zip
- https://www.postgresonline.com/downloads/pg17http_w64.zip
- https://www.postgresonline.com/downloads/pg18http_w64.zip

These complete 64-digit hashes and sizes come from the actual original Linux PR Run [42951353844](https://github.com/pgextwin/catalog/actions/runs/42951353844), as recorded in [Issue #112 comment 6785971351](https://github.com/pgextwin/build/issues/112#issuecomment-6785971351). Each URL is exactly `https://www.postgresonline.com/downloads/pgXXhttp_w64.zip` for its major. These are HTTP-response byte observations, not authenticated producer pins. The earlier local PG18 retrieval failure remains historical evidence. No Windows runtime result is implied by that earlier Linux run.

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


## Independent Windows re-GET and runtime pilot

The PR-only `issue112-http-windows-runtime.yml` reuses the immutable shared Build installer for EDB PG14–18. `issue112_http_windows_runtime.py` independently re-downloads each exact publisher URL with redirects prohibited; requires equality with the above size/SHA256; reuses the existing ZIP/CRC/path/AMD64 guards; then stages only bin DLLs, lib/http.dll and http SQL/control files in the disposable host. Every existing bin dependency is preserved and hashed; a non-bin collision fails before staging. The extra_depends tree is excluded from this test and is not claimed unnecessary for other environments.

The test requires actual CREATE EXTENSION, the expected publisher-advertised installed extension version, and http_get against a bounded loopback fixture. It captures the live tested PostgreSQL backend modules after that request, including their actual loaded paths and SHA256, requires the candidate http.dll path and an observed libcurl module, and verifies all preinstalled host DLLs remain unchanged. This covers only that request on that host. It does not prove HTTPS/TLS, every runtime branch, complete static/dynamic dependency closure, source/build provenance, component licenses, or production installation safety. A failed or skipped matrix job is not a successful acceptance.

No downloaded archive or staged binary is uploaded. Public index, signed cohort, Build issuer, CLI transport, Environment, Publisher and Release policy remain unchanged. These are older community binaries, not upstream source v1.7.2. All public GET/mirror/Release authorizations remain denied; passing this pilot alone cannot promote them.
