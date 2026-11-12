# Issue #112 — PGroonga 4.1.0 transitive static imports × rights candidates (deny-only)

Status: **CANDIDATE_ONLY / PUBLIC_GET DENY / MIRROR DENY / RELEASE DENY / PUBLISH DENY**.

The existing five-major original ZIP auditor pins and hashes official PGroonga 4.1.0 ZIPs. Existing separate source-only rights joins enumerate 43 DLL/EXE member receipts and 25 legal-document candidates per major; existing static PE import audit lists ordinary/delay imports. This step **joins those two observations on one independently rehashed original ZIP**, then traces their transitive *names* without claiming real loader resolution or legal satisfaction. It does not rebuild the CLI or modify admission policy.

For PG14–18, the new path-only, contents:read matrix:
1. Downloads each original **only in its new verification job** and rechecks the exact 4.1.0 SHA256/size, ZIP member paths/CRC and binary/document receipts. Existing successful historic runs are not rerun.
2. Reuses the existing PE parser. It rejects an unpaired asset/version/major, extra/omitted PE rows, duplicate and spoofed members, unsafe imports and unknown analysis states.
3. Reports exact per-binary SHA256, direct candidate bundle import paths, transitive static reachability, component-group hints and any reachable binary lacking a named legal-document candidate (notably xxHash). Ambiguous duplicate basenames and all imports absent from the package are **unresolved**, never silently assigned to Windows/EDB or another candidate.
4. Preserves explicit false gates for effective Windows loader origin, optional dynamically loaded modules, complete applicable notices, mutable historical `groonga-latest.zip` source SHA, source-to-ZIP signed attestation and current authenticated owner/Environment/Publisher authorization.

**Important limits:** A reachable DLL basename is neither a verified same-PID loaded path nor a component version/source identity; this graph adds no proof about optional plugin LoadLibrary edges, embedded/static libraries, fully applicable upstream licenses (including MRuby inherited terms), or notice delivery. The signed final PGroonga ZIP and historical upstream Actions run are already separately verified but cannot retroactively supply a cryptographic record of the mutable Groonga build input. All the resulting gap/rights fields intentionally stay false, even when the imported graph is internally complete. This matrix is a triage mechanism to direct real rights resolution, not a formal GET admission or redistribution license.

The exact historical producer context remains [producer boundary](issue-112-pgroonga-producer-boundary.md); [rights intake](issue-112-pgroonga-rights-intake.md), [candidate joins](issue-112-pgroonga-rights-join.md), and [source terms review](issue-112-pgroonga-source-terms-review.md) remain separate evidence. The previous 8 original matched loaded DLLs plus 1 EDB LZ4 observation per PG major is **not** generalized to every binary by this static analysis.

No original third-party ZIP or source binary is uploaded; no token, signature, public feed, Release, formal publisher, Website or external GET operation is invoked. Native already-public releases and the expired 11-ZIP admission remain untouched.
