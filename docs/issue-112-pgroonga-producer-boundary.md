# Issue #112 — PGroonga 4.1.0 original producer-chain boundary (deny-only)

**CANDIDATE_ONLY: PUBLIC_GET/MIRROR/RELEASE/PUBLISH DENY.**

This new audit reuses the already independently accepted original ZIP and Groonga
OpenPGP detached signature evidence (Catalog PR #366, protected-main push Run
43287270656). It performs no successful Run replay, provider ZIP download, signing,
CLI changes, owner admission, Publisher invocation or Release creation.

## Exact authenticated upstream GitHub evidence

The read-only workflow queries the actual upstream REST API with a scoped
contents-read GitHub token and rejects altered, incomplete or unsafe replies.
It validates the complete five-major official PGroonga 4.1.0 Release ZIP/.asc
metadata using the previously protected strict baseline before any run evidence.

The official annotated source tag object
a40db64f8e4761d3dc00b457faabf00d0613a711 resolves to commit
47d0252f76dccbdc2ebeee9ed6cf941dd9552bcc.
**The tag is unsigned** (GitHub API verification reason: unsigned).
A signed original release ZIP does not sign the tag or source inputs.

The official Windows run 37872644159, original push, attempt 1 and SUCCESS,
has separate matching PostgreSQL 14–18 jobs with successful Configure Groonga
and Package steps. Their exact IDs are pinned in the audit. The original
Release run 37872644104 was successful on **attempt 2**, not attempt 1,
at the same commit. Its GitHub job downloaded upstream Actions artifacts
and published the Release. Wrong actor, event, attempt, status, head or
individual skipped step is rejected.

Five exact outer GitHub Actions artifact IDs, compressed byte sizes and API
SHA256 hashes are pinned, including strict exclusion of the sixth
Groonga-main development artifact. These **outer archive** hashes are not
the independently rehashed 53-MB inner Release ZIP hashes. Historical
artifact-to-Release ZIP identity and detached signatures are separately
recorded earlier in Issue #112 and are not claimed as fresh evidence here.

The source-read audit verifies Git blob SHA1 computed over the real,
length-prefixed upstream workflow text at the immutable tag commit:
- Windows workflow: c1b2497d4f43e969214ff30ccbe846ebdc7c146c
- Release workflow: 495623c715629761a978e22a83be9269a1b5c5f3

## Original Release job execution log narrows the Run-selection ambiguity

An authenticated GitHub GET of official original Release run `37872644104`
(attempt **2**, success), job `113650372251`, returned the **actual job log**.
At 2026-10-09 03:23:32 UTC the job printed:

```text
Waiting for run to start windows.yml...
Run Windows (37872644159) has already completed with 'success'
```

The same job's original `Download artifacts` and `Publish` steps both
completed successfully. The audited job log thus gives a concrete observed
Windows producer **Run ID 37872644159** instead of inferring the selected
run from the mutable `gh run list --limit 1` workflow source alone.
A strict original-job-log check now matches this exact one successful Run,
rejects another Run/result or missing log context, and never treats logs
as a cryptographically signed source-to-binary attestation.

This reduces the historical **Release-to-Windows-Run selection** uncertainty.
It does **not** supply a SHA256 for the mutable
`groonga-latest.zip` downloaded by the original Windows job, prove source
dependency identity, or authenticate the entire build toolchain. Original
ZIP/OpenPGP signature and Actions-artifact identity remain independently
verified prior evidence; rights/NOTICE and owner/Publisher admission remain
separate DENY gates.

## Original five-major Windows job logs confirm the mutable source command

The official original Windows Run `37872644159`, attempt 1, has separate
PostgreSQL 14–18 job logs. Each shows the **non-Groonga-main** source-download
branch (`if ("" -eq "yes")`), the
`Invoke-WebRequest https://packages.groonga.org/source/groonga/groonga-latest.zip`
command, extraction and deletion of the downloaded archive, the exact
`release-postgresql-<major>-x64` artifact name, version 4.1.0, and
progression into `Configure Groonga`. GitHub reports all original jobs and
their required downstream build/package steps successful. The audit reads all
five exact job IDs through bounded authenticated GitHub API GET, and permits only
token-free HTTPS result-storage redirects. Swapped PG-major context, a different
input URL, a Groonga-main branch, missing step context, duplicate URL or oversized
log is rejected by the verifier and offline adversarial tests.

**Boundary:** The original log echoes the selected *command*, not the SHA256
of the HTTP response body. It does not prove that all five jobs downloaded
identical source bytes, that the current URL serves the historical bytes,
or that the download, compiler and dependencies were covered by a signed
producer provenance statement. Historical input SHA256, rights closure and
owner-specific formal publication remain **DENY**.

## Remaining producer and third-party blocker

The exact original Windows workflow obtains the mutable input
https://packages.groonga.org/source/groonga/groonga-latest.zip without a
recorded input SHA256 or pinned source commit. The original Release workflow uses gh run list --limit 1 before gh run download.
The original job log now **observes** Run 37872644159 selected, but workflow
source by itself and unsigned logs are not signed input provenance. Valid original
signature bytes and successful named workflow jobs do not establish a
signed, fixed source/toolchain/dependency-to-binary provenance attestation.
Groonga 16.1.3 package version markers cannot stand in for the historical
input digest. Third-party licensing/NOTICE issues (including xxHash and
MRuby-derived terms), complete per-binary component mapping, runtime
dependency closure and owner-signed source-specific Publisher admission
also remain unresolved.

Adversarial offline tests reject forged tag claims, changed actor/event/run
attempt, fake job success, archive substitution, swapped workflow blob and
permission escalation. The read-only CI never publishes, mirrors or signs
an admission. The original provider must supply genuinely traceable signed
build-input evidence (or produce a new formally bound, pinned build), plus
independent rights and dependency closure, before the existing protected
owner/Environment/Publisher gates may be considered.

**Result: independently checked historical producer metadata and an explicit
unclosed signed producer-input boundary, not formal GET authorization.**
