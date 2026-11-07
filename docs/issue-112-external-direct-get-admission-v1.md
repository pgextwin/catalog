# Issue #112 — source-specific direct GitHub original-GET admission design (v1)

**Current acceptance: CANDIDATE_ONLY / NONPUBLISHING.** The protected source request
and generic fail-closed validator are a *new preparatory component*, not an
authorization issuer, signed Catalog feed, published external Release, or enabled
CLI endpoint. The existing pgextwin CLI v0.3.6 and native/offline paths are
unchanged.

## Why the old design never progresses

The existing \`config/issue112-external-publisher-policy.json\` / strict
\`external_formal_publisher_policy.py\` **deliberately require**
\`formalSourceSpecificAuthorization=false\`,
\`originalMainIndependentSigstoreVerified=false\`, and
\`approvedOperation=NONE\`. They always return
\`formalAdmissionReady=false\`. This is a project-controlled **hard deny**, not
evidence that upstream GitHub Release owners forbid end-user downloads.
Neither an owner chat instruction nor a synthetic PR test should be converted
into an authorized source-specific GitHub event.

The initial official oracle_fdw 2.9.0 PG18 and unofficial community pgvector
0.8.7 PG18 remain under their earlier separate P3 long-term hold. **Do not**
edit those policy booleans to true or claim that the old signed deny-only
candidate is a public, authorizing external feed.

## New operation separation

| Operation | Definition | Policy |
| --- | --- | --- |
| Original-provider GET-only | A user runs pgextwin CLI and obtains an unchanged original GitHub Release ZIP directly to that user's local disk; verify repository/release/asset IDs, original SHA256, byte length and ZIP safety before an atomic write. | May be admitted **only per source/asset** after independent checks and an authenticated, independently signed Catalog admission. No proxy, repackaging, installation, public rehost or fallback. |
| Mirror or redistribution | pgextwin stores, uploads, modifies, serves or republishes third-party ZIPs or dependent DLLs. | **DENY**, requiring a separate explicit rights and formal publication process. Neither GET-only approval nor an upstream Apache-2.0 source license silently permits these operations. |

## Completed preparatory contract in this PR

- \`config/issue112-pg-trickle-direct-get-intake-v1.json\` pins one
  **upstream-official** source: \`trickle-labs/pg-trickle\` v0.108.3, EDB
  PostgreSQL 18.6.5 Windows x64, repository ID \`1164857056\`, Release ID
  \`404988260\`, asset ID \`616203967\`, immutable original ZIP size
  \`7029107\` bytes, and SHA256
  \`c2841dacee6fa1a09400c7e9a0f74159f2b7f36847a60ef10291d1beb06bd96b\`.
- Existing genuine, completed protected-main Windows runtime
  [Run 41870312567](https://github.com/pgextwin/catalog/actions/runs/41870312567)
  (\`push\`, attempt 1, success) is a reusable **runtime evidence pointer**,
  not permission. The original upstream Apache-2.0 LICENSE is present in
  independently rehashed ZIP evidence; independent third-party notice and
  runtime dependency closure are NOT represented as accepted.
- \`scripts/external_direct_get_intake.py\` implements a generalized,
  deny-only intake parser with exact keys, strict duplicate-key rejection,
  source-specific IDs, HTTPS-only exact GitHub original URL, byte
  SHA256/length, PG/ABI scope, license and dependency review fields, claimed
  original Windows evidence and duplicate/source-collision protection.
  It reuses \`external_direct_link_review.strict_read\` and
  \`external_provider_release_identity.compare_exact_source\` for
  exact GitHub repository/Release/asset metadata comparison, instead of
  duplicating an asset authenticity implementation.
- An API snapshot accepted by the script must be obtained by an independently
  authenticated GitHub GET in the actual caller. **Passing JSON to the parser
  does not authenticate the API or any Run.** Neither a matching digest from
  GitHub nor a self-declared runtime Run ID is a signed authorization.
- Adversarial tests try operation escalation, native Publisher substitution,
  unauthorized/held source promotion, tag/URL/asset switching, release
  draft/identity substitution, duplicate JSON, invalid Run evidence, and
  direct/mirror permission flips. A successful test remains \`PUBLISH_DENY\`.

## Required issuance design (not completed by this PR)

The authorizing identity must be the dedicated
\`external-direct-provider-publisher\` GitHub Environment with its
least-privilege scoped App, **not** the native \`publisher\` App or the local
intake JSON. A future separately reviewed protected implementation must:

1. Obtain a *new permitted authentic owner-specific source approval* at
   exact asset identity and operation \`ORIGINAL_PROVIDER_GET_ONLY\`,
   bound to the genuine GitHub actor, event, original Run/attempt, protected
   main HEAD and actual Environment reviewer. The previously denied
   Issue #112 owner-event route must **not** be replayed, disguised or
   bypassed. Without a legitimate source-specific authorization
   issuer, stop at CANDIDATE_ONLY.
2. Independently reauthenticate GitHub repository/Release/asset identity,
   license/NOTICE, dependency ABI and existing Windows runtime Run; rehash
   original bytes inside the authorized private verifier.
3. Generate the exact approved external Catalog original-byte pin using
   authenticated original-main GitHub Actions OIDC/Sigstore; verify actual
   bytes, signer workflow SAN, OIDC issuer, source SHA, main, provenance and
   transparency proof in a **separate verifier** before create-only
   publication of metadata. Do not treat the pre-existing deny-only
   signed candidate as that permission.
4. Only then extend the CLI's signature-verifying feed consumer so a signed
   \`ORIGINAL_PROVIDER_GET_ONLY\` entry can call the already merged
   \`ExternalProviderAssetTransport\` and \`ExternalOriginalBatchStager\`.
   Require the exact approved source, PG and provider-byte pin, and ensure
   no network call occurs when admission is absent, tampered, out of scope,
   revoked, expired, or unsigned.
5. Run genuine Windows provider-original-byte end-user CLI E2E plus malicious
   input/rollback tests, required exact-head PR CI, protected merge, original
   postmerge, and distinct official Publisher acceptance if required.

### Do not confuse the statuses

A true input match proves only a *candidate identity check*.
A signed **deny-only** private candidate proves a signer's process, not
authorization. Only a technically authenticated issuer and independently
verified, scope-limited authorizing signed Catalog pin may enable the CLI GET.
No ZIP is distributed or mirrored by this proposal.
