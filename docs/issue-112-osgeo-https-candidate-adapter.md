# Issue #112 — exact OSGeo HTTPS original candidate transport (NONPUBLISHING)

**CANDIDATE_ONLY / GET_DENY / MIRROR_DENY / RELEASE_DENY.**

This is an isolated internal .NET candidate adapter for exactly one verified original:
`postgis-bundle-pg18-3.7.0x64.zip` (83,320,975 bytes, SHA256
`fa3db8060d8d376e869d961659bf4eff326c0d99a731396701af61a13dc12a40`).
There is **no CLI, signed-feed, issuer or Publisher caller**. It cannot authorize
or implement user-facing OSGeo GET.

- Exact official HTTPS URL only, no off-origin or query substitution, no
  automatic redirect, mirror, credential, cookie, or fallback. A failed
  HTTP response never causes a different-source retry.
- Reuses original ZIP SHA256, length, path traversal, symlink, duplicate-case,
  decompression and CRC checks, and atomic create-only output.
- The existing generic GitHub Release verifier still enforces a **64 MiB**
  ZIP maximum, **1,000** entries and **256 MiB** total expanded content.
- Only this exact OSGeo original gets a bounded **96 MiB** ZIP allowance,
  **25,000** entries and **2 GiB** expanded budget. This is necessary for
  the observed **1,041** original ZIP members, not a general relaxation.
  Any future bundle version must have new independently reviewed byte pins.
- Synthetic offline tests cover forged pin, wrong PG major, HTTP 302/404/503,
  forged HTML, wrong content length, destination collision and no fallback.
  The tests do not make a live OSGeo request.

The adapter is a transport-only preparatory unit. Producer source-to-exact
binary provenance, full component licenses/NOTICE, cross-host runtime
dependencies, authentic owner `workflow_dispatch`, independent Sigstore
source-specific admission, signed Catalog binding, release authorization,
public Windows CLI real GET and Website E2E remain unfulfilled.

Do not connect the candidate class to a command, signed feed, issuer or
publisher without those separately reviewed protected gates. Existing
`download-all --source external` behavior remains unchanged.
