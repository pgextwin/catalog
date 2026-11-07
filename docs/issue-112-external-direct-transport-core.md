# Issue #112 — isolated external original-provider GET core (NONPUBLISHING)

Status: **transport-only preparation; external CLI download remains DOWNLOAD_DENY**.
This change is not an external Release, a provider authorization, or a signed
Catalog external pin. Existing \`cli-v0.3.6\` and native ZIP downloads are unchanged.

## Scope and guard

The new internal \`ExternalProviderAssetTransport\` is intentionally **not**
wired to any CLI command, user-facing downloader, discovery registry, or
Publisher. It cannot be used through \`download-all --source external|all\`.
No external ZIP is downloaded in CI or stored/mirrored in pgextwin.

Once a future independently reviewed authorization and signed external Catalog
pin is available, a separate protected change must admit exact provider pins
and call this transport. Raw discovery files, locally supplied ledgers, and
the current publisher policy cannot create that admission.

Current source-specific policy is still
\`formalSourceSpecificAuthorization=false\`,
\`originalMainIndependentSigstoreVerified=false\`,
\`approvedOperation=NONE\`, and both initial two providers have
\`downloadAuthorized=false\`. Do not modify or bypass these flags.

## Shared technical pieces

- Original provider repository, release tag and numeric repository/release/asset
  IDs, original asset filename/URL, original byte size and SHA256 are immutable
  inputs checked before and during GET.
- Provider repository metadata and exact-tag Release inventory are read from
  GitHub REST GET; exact numeric asset-ID GET is the only binary endpoint.
- Redirects are finite, HTTPS-only and restricted to GitHub's trusted Release
  asset domains. HTTP errors, identity changes, duplicate assets and forged
  URLs fail closed without alternate provider fallback.
- Existing \`ExternalOriginalZipIntegrity.Verify\` is reused for exact digest,
  size, ZIP structural, path traversal, symlink, CRC and expansion bounds.
- A verified original is written to a unique \`.part\` file in an existing
  physical output folder and atomically renamed without overwriting a
  pre-existing file. Failed checks leave no output bytes.
- This single-file transport is **not** the native atomic bulk transaction.
  External bulk staging, authenticated signed source pins, CLI selection and
  authorized Windows provider real-byte E2E remain separate work.

## Contract test coverage

Local synthetic network handlers exercise 4 different provider ZIP naming
patterns (oracle_fdw, pgvector community, pg_trickle, portalcorp) and
repository-ID substitution, asset-ID substitution, tampered bytes, off-host
redirects, HTTP 403, URL forgery, and destination collision. Tests never
contact those providers, so a green CI must not be reported as a real external
provider GET, provider rights approval, external signature validation, or
PUBLIC_COMPLETE.

## Exit criteria for next independently useful unit

1. A protected and independently signed external Catalog pin/admission format
   that binds one real provider's identity, bytes, rights, runtime and source-
   specific authorization without changing the existing two-provider P3 hold.
2. Shared all-or-nothing batch staging with externally named original assets,
   authenticated pin readback and strict no-mirror behavior.
3. Genuine Windows authorized real-provider GET E2E and hostile regressions.
4. Required PR CI, protected merge, original postmerge, then any applicable
   independent signature and Publisher checks; no publish on a skipped gate.

Do not interpret this pre-admission transport as source-specific authorization.
