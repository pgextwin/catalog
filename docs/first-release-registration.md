# Protected first signed-Release registration

A future extension must be explicitly added through a protected Catalog PR to
`config/first-release-registry.json`. This is the single source for new
upstream identities, display name, description and license; Python intake,
drift detector and first-Release verifier share the imported declaration.

The sealed historical 14 sources remain unchanged. The three existing
Wave 3 sources are pinned against mutation. Merely adding a manifest entry
does NOT authorize Release publication, signing, Catalog auto-merge or a
Website deployment. The central protected fleet must independently admit the
new repository; genuine signed public ZIP/SPDX/Grype, Sigstore attestations,
SHA256, source identity, exact-head App15368 CI and formal-release publisher
gates must all pass. Unknown identities still fail closed.

Current PUBLISH_DENY, manual-only, and Catalog auto-merge disabled settings
are preserved. Never introduce a new entry purely to simulate a real Release.
