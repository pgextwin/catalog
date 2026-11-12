# Issue #112 — TimescaleDB 2.31.0 PG16–18 component-rights/provenance intake

**State: CANDIDATE_ONLY / NONPUBLISHING.** This is a source-document audit,
not legal advice, source-to-binary attestation, source-specific owner authorization,
or permission to download on behalf of users. All four public operations remain
**PUBLIC_GET_DENY / MIRROR_DENY / RELEASE_DENY / PUBLISH_DENY**.

## Independently attributable upstream source documents

On the immutable upstream `timescale/timescaledb` tag `2.31.0`
(Release ID `418582851`), these Git blob identities were observed using
the authenticated GitHub connector:

| File | Git blob SHA | Meaning (source only) |
| --- | --- | --- |
| [LICENSE](https://github.com/timescale/timescaledb/blob/2.31.0/LICENSE) | `6b7980745c9892ba0d79368acab331dea2246ac2` | Outside `tsl/`: Apache 2.0, unless the file says otherwise. Inside `tsl/`: Timescale License, unless noted. Separate shared objects for Apache and TSL are described. |
| [LICENSE-APACHE](https://github.com/timescale/timescaledb/blob/2.31.0/LICENSE-APACHE) | `f433b1a53f5b830a205fd2df78e2b34974656c7b` | Full Apache-2.0 text. |
| [NOTICE](https://github.com/timescale/timescaledb/blob/2.31.0/NOTICE) | `a47a53c48d921bef9023e41e8def002d45465a7d` | Timescale copyright, PostgreSQL license and other source notices. Does not independently enumerate the contents of each downloadable ZIP. |
| [tsl/LICENSE-TIMESCALE](https://github.com/timescale/timescaledb/blob/2.31.0/tsl/LICENSE-TIMESCALE) | `e92b2d902723571c921cfe59b841e6d7ab40f30d` | Section 2.1(c) conditionally permits distribution of **unmodified standalone** source/binaries; section 2.2 restricts uses and redistribution. This is not a blanket ban or blanket authorization. |

The source-level distinction must **not** be treated as proof of which DLLs,
installer bytes, runtime dependencies or notices were actually included in the
three original Windows ZIPs. The upstream `CMakeLists.txt` has
`APACHE_ONLY` default OFF; this is a build-system default, **not proof of the
producer's actual Release build flags**. The upstream
[Windows package workflow](https://github.com/timescale/timescaledb/blob/2.31.0/.github/workflows/windows-packages.yaml)
**downloads and tests** the current Windows package; it alone does not attest
the precise build inputs and output hashes of Release assets 659788299,
659795995 and 659790321. An upstream Windows build-and-test workflow exists,
but no verified direct source-commit/Run-to-these-three-Release-asset binding
has been established in this audit.

## Component / evidence matrix

| Scope | Observed | Remaining proof before admission |
| --- | --- | --- |
| Core source outside `tsl/` | Apache-2.0 or per-file compatible exceptions | Match the **exact DLL** byte identities and relevant file licenses; verify notice delivery. |
| `tsl/` source and binary | Timescale License; separate TSL shared-object family documented | Identify actual TSL DLLs in each original ZIP; verify unmodified status, section 2.1(c)/2.2 applicability, and required license presentation. |
| PostgreSQL-derived source and other incorporated components | Upstream `NOTICE` cites PostgreSQL rights | Enumerate all transitive/embedded components, copyrights, NOTICE and license obligations per ZIP. |
| Windows installer and runtime dependencies | Upstream `timescaledb/setup.exe` tested by pgextwin on Windows | Attribute installer and dependent DLLs to the producer inputs; dependency closure and legal notices remain unverified. |
| Original provider Windows ZIPs PG16, 17, 18 | Independent actual-byte SHA256 + disposable Windows PG SQL test PASS in #322/#325 | Producer source-to-binary signature, component closure and new owner-signed source-specific direct GET authorization remain absent. |

Reference [original-byte audit](issue-112-timescaledb-original-rehash.md)
and [Windows SQL audit](issue-112-timescaledb-windows-runtime.md).
The ZIP identity/size/hash rows are pinned in
`external/timescaledb-rights-provenance-intake-v1.json` and strictly
cross-checked against the existing
`external/timescaledb-release-watch-baseline-v1.json`. The JSON records
unresolved gates as `UNVERIFIED` or `MISSING`, never as `PASS`.


## Exact original ZIP filename-level legal/NOTICE observations

**No original Run was rerun**: the following entries are extracted from the
existing successful, authenticated
[TimescaleDB original rehash Run 43116446694](https://github.com/pgextwin/catalog/actions/runs/43116446694)
and individually identified genuine original Windows ZIP audit jobs.

| PG | Original Run job | ZIP members | DLL members | Declared expanded bytes | Potential LICENSE / NOTICE / COPYING filenames |
| --- | --- | ---: | ---: | ---: | --- |
| 16 | 130845554299 | 77 | 3 | 33,783,221 | **0** |
| 17 | 130845554217 | 77 | 3 | 33,783,221 | **0** |
| 18 | 130845553821 | 77 | 3 | 33,785,269 | **0** |

The original auditor's `zipInventory.potentialNoticePaths` array is empty
for all three original provider archives. Its name test is
`(?:^|/)(?:licen[cs]e|notice|copying|third.party)(?:[./_-]|$)`,
case-insensitive. Its result is **only a ZIP path-name inspection**: it
does **not** verify the embedded setup.exe contents, binary resources, an
alternative-named document, or license/NOTICE text outside the ZIP.
Consequently neither document absence in every possible location nor
legal noncompliance is proven. But **bundled license/NOTICE completeness is
not verified**, so publish permission remains **DENY** and cannot be
derived from exact ZIP SHA256, Windows SQL tests or this intake. Relevant
upstream source `NOTICE` and `tsl/LICENSE-TIMESCALE` exist separately
at tag `2.31.0`; their presence in source is not evidence of shipping them
to end users.

The archived original findings are pinned in the JSON ledger. The offline
guard rejects tampered job IDs, member counts, purported notice paths,
invented legal clearance and substituted provenance. Need per-binary
component/license mapping, any necessary downstream notice delivery method,
verified upstream build identity and an independent new scoped owner
signature before any direct GET admission.

## Acceptance still required

1. Inspect **each exact original ZIP** offline for all LICENSE/NOTICE files,
   DLL and executable names, dependencies, and SHA256; map each actual binary
   to the upstream source scope/license and identify any missing notices.
2. Obtain verifiable **producer source-to-Release-binary provenance** for each
   original PG16/17/18 ZIP, including immutable tag/commit, build Run,
   toolchain/dependencies, CMake flags, and signed exact output digests.
3. Review legal terms for **pgextwin direct-provider-only end-user GET** and
   any intended mirrors/redistribution *separately*. A license possibility
   or independent hash is not a new source-specific owner approval.
4. If every prerequisite is satisfied, create a **new, genuine, scoped owner-signed
   authorization** through the protected approved design. Never reuse a
   Publisher approval, archived signed evidence or expired issuer. Require a
   separate protected PR, CI, postmerge and genuine user-facing original-byte
   E2E before any `PUBLIC_COMPLETE` claim.

Run read-only guard: `python scripts/issue112_timescaledb_rights_gate.py`
and `python -m unittest discover -s tests -p 'test_issue112_timescaledb_rights_gate.py'`.
The guard merely verifies the current known-DENY evidence contract. Its PASS
is explicitly **not** legal clearance, a digital signature, or publishing approval.
