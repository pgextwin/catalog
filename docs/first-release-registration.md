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

## Package ledger and Website view

After the signed Release is public, use the existing verified Release sync
workflow. It verifies the published bytes, signatures and version-specific
license evidence, then writes `packages/<extension>.json` and generates
`extensions/<extension>.json`. First intake also updates the Catalog index and
the existing Landscape registration as needed. Review the verified PR and
merge it with a merge commit after its checks pass.

The ledger is the source for both the v3 signed feed and the Website's v2
record. Each Release has a GitHub ID and per-major ZIP rows with the actual
package version, asset ID, SHA-256 and license evidence. `latestReleaseId`
selects the current Release. A superseded version that remains available
retains its original pins and the first-parent main commit that admitted it.
Removing a historical row from the ledger withdraws it from subsequent feeds.

When changing Catalog metadata manually, edit the ledger and regenerate the
Website view from the repository root with
`python scripts/package_ledger.py <extension>`. The feed projects the cohort
configured in `config/cli-feed-majors.json`, with PostgreSQL 14 excluded.
