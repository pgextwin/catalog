# Issue #112 — PGroonga 4.1.0 real original ZIP detached signatures (nonpublishing)

**CANDIDATE_ONLY. PUBLIC_GET/MIRROR/RELEASE/PUBLISH DENY.**

This audit extends, without replacing, the protected PGroonga 4.1.0 official
Release ZIP metadata and detached-signature asset identity checks from Catalog PR #365.

The signer key is selected **independently of the self-reported .asc key ID**:
Groonga's official repository file
`groonga/groonga@git:b4c1e7f13254e619dbdf0eeb164186b244ce07ae/gpg_uid_rsa4096`
and the official `ci/msys2/PKGBUILD` identify the full fingerprint
`2701F317CFCCCB975CADE9C2624CF77434839225`, Groonga official signing key
(`packages@groonga.org`). The CI fetches that immutable upstream fingerprint
and the public-key material from the project's
`https://packages.groonga.org/debian/groonga-archive-keyring.asc`.
It imports into an isolated temporary GnuPG home and exports **only** the
fingerprint-matching key to a separate gpgv keyring. Neither keyservers nor
the .asc packet's advertised key ID are treated as signing authority.

For each selected PG14–18 major, the read-only CI cross-checks the exact
Release asset metadata against the preexisting protected fixed asset ID, byte
length and SHA256 records, then downloads the **real original public** 53 MB ZIP
and its 833-byte .asc. Both receive independent bounded length and SHA256
verification. `gpgv` must then validate the actual ZIP/sidecar pair and report
a valid signature tied to the full pinned fingerprint. Offline tests create a
throwaway real GPG key and signature and verify wrong-key, tampered-ZIP,
corrupt-signature, unsafe URL/bound and pre-existing-destination denial.

A cryptographically verified Groonga signature proves that the particular
hashed ZIP bytes were signed by the key identified by the independently
sourced project fingerprint. It does **not** prove which upstream Windows CI
inputs produced that ZIP, exact signed source-to-binary build provenance, a
complete third-party component license/NOTICE/dependency closure, pgextwin
owner approval, dedicated Publisher Environment authorization, or any
right to serve/mirror/repackage those ZIPs. Release uploaders and upstream
workflow runs remain distinct facts, never substituted for signed provenance.

No production CLI, distribution feed, owner-signature policy, release,
token or Publisher authorization is changed by this audit. A failed fetch or
fingerprint/cryptographic mismatch must fail closed. Existing successful
Run executions are not rerun solely to manufacture new evidence.

The goal remains expanded current-version PG14–18 and version-selectable
external **original-provider GET-only** cohort (PostGIS/pgRouting latest bundle
allowed), after all actual source- and publisher-specific gates are met.
