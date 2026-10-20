# Normal Chat: verify a public Release without Dispatch or a new App

This read-only route reuses `verify_signed_fleet_release.generate` and the
existing authenticated bounded GET reader. It cannot publish a Release or
modify Catalog main. It is separate from any human UPDATE/PUBLISH authorization.

After an actual signed formal Release exists, normal Chat may create a branch
`catalog-verify/<extension>-<releaseTag>` from current protected main, adding
exactly one `.github/catalog-release-requests/<extension>-<releaseTag>.json`.
The exact eight keys are `schemaVersion` (integer 1), `type`
(`pgextwin-public-release-catalog-verification`), `extension` (one of the existing
17 verifier identities), `releaseTag`, `releaseId` (actual positive public GitHub
Release ID), `catalogBaseSha` (fresh full main SHA), `operatorLogin`
(`ShutenOishi`) and `confirmCatalog` (`VERIFY_PUBLIC_RELEASE`). Do not create a
placeholder or a request for a candidate ZIP.

Run the existing required `validate` at the exact PR head, then safely squash
merge. The main-push workflow independently verifies actual human identities,
signature/single-parent merge, exact PR/blob and App15368 head CI, current main
and public Release ID. It delegates every ZIP/SHA256/SPDX/Grype/SLSA/SPDX/source/
PG check to the existing genuine public signed-Release verifier, and rechecks
the stable Release/asset identity snapshot before exposing a record artifact. Invalid, missing,
unpublished, unsigned, changed-ID, duplicate or stale evidence denies. A setup
push without a request returns `NO_CATALOG_REQUEST` and verifies no Release.

Only after the real run succeeds may normal Chat retrieve
`verified-catalog-chat-request`, inspect the generated record against latest
main and create the normal single-extension Catalog record PR (and initial
index addition only where permitted). Require native CI and independently
verify the existing Website JA/EN public audit after merge. The existing
catalog-only proposer App may still be used through its separately configured
route; this path needs no App, key or write token. No automatic merge, Release
write, new permission, secret, catalog record or index expansion is introduced
by the setup. CLI v0.3.2 and the exact 14→17 intake policy remain intact.

This closes the Dispatch dependency for **Catalog read-only verification**.
No real third-wave Release currently exists, so third-wave signed E2E remains
unproven and #75 GO B/G4/G5 and formal Release DENY are unchanged.
