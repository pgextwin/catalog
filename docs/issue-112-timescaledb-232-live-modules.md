# Issue #112 — TimescaleDB 2.32.0 live Windows DLL module origins

**CANDIDATE_ONLY / PUBLIC_GET_DENY / MIRROR_DENY / RELEASE_DENY / PUBLISH_DENY.**

This independent, nonpublishing PG16–18 Windows test reuses the reviewed
2.31.0 live process sampler, approved EDB installer, exact-original ZIP
staging, SQL/hypertable test, PE import parser and strict receipt join. It
uses `--version 2.32.0` everywhere: 2.31.0 remains the default for the
historical workflow and is not used to authenticate the latest original.

Before any live module receipt can be accepted, the 2.32.0 static import
receipt must match the independently validated protected original evidence
ledger for the exact PostgreSQL major: Release 442824242, asset ID, ZIP
SHA256 and actual byte length. Version-mixed DLLs or runtime samples, mismatched
origins, missing matched TimescaleDB DLL bytes, false public permissions,
unparsed PE tables and malformed receipt data are rejected.

The Windows worker samples only genuine matching disposable EDB PostgreSQL
processes while the reviewed 2.32.0 upstream setup and real SQL exercise
run. For each observed module of interest it records the loaded file path,
SHA256 and observed Authenticode status, then removes temporary original
payloads and receipts. **This is sampling, not complete loader resolution**:
unobserved or lazy paths, API-set forwarding, every dependency DLL,
all component rights and notices, embedded setup.exe content and signed
producer source-to-asset provenance remain unverified.

The original provider bytes are only read in isolated CI. No binary ZIP is
uploaded, mirrored, released or newly admitted to public GET. Passing this
test never supplies producer signatures, owner-source-specific approval,
Environment/Publisher authorization or a new signed external issuer. The
expired 11-ZIP cohort may not be replayed. Existing native releases and
the CLI's latest, --pg, --extension and --version selectors are unchanged.
