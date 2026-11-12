# Issue #112 — PGroonga 4.1.0 official detached-signature sidecar intake

**CANDIDATE_ONLY / PUBLIC_GET_DENY / MIRROR_DENY / RELEASE_DENY / PUBLISH_DENY.**
This is a read-only candidate evidence step, not the detached-signature cryptographic verifier,
source-to-binary attestation, trusted maintainer key or release authorization.

The official pgroonga/pgroonga Release 407467158 has five PG14–18 original ZIPs
(already independently rehashed by the existing protected review), plus five
corresponding .zip.asc assets. The latter are uploaded as groonga-release,
separately from the ZIPs published by github-actions[bot]. This does not prove
that either uploader signed the payload or that any detached signature is valid.

The new validator joins *all five* official ZIP asset IDs, lengths and SHA256s
from the existing protected metadata baseline with the exact five .asc asset
IDs, fixed 833-byte lengths, SHA256 digests, expected URLs and uploader labels
from separately authenticated GitHub Release REST metadata. It independently
GETs **only the five tiny detached signature files** (not the 53 MB ZIPs), verifies
their SHA256 and byte lengths and parses an OpenPGP key-ID **hint**. No key is
trusted, no gpgv verification is performed and no signer fingerprint is
accepted from the self-identifying packet. The earlier ZIP rehash and
original upstream Windows CI are reused, not rerun.

Upstream pointers (not source-to-asset cryptographic proof): the upstream
annotated 4.1.0 tag targets commit 47d0252f76dccbdc2ebeee9ed6cf941dd9552bcc;
Windows build Run 37872644159 was push / attempt 1 / SUCCESS, and Release
Run 37872644104 was push / attempt 2 / SUCCESS. Original artifact IDs do
not by themselves prove the released asset bytes were signed by the producer.

Offline hostile tests reject wrong Release, changed sizes or digests, duplicate
asset names/IDs, false download permission, sidecar uploader substitution,
unsafe URL, missing PG major, malformed armor and duplicate JSON. The workflow
is PR and original-push scoped, contents: read only, and has no artifact upload,
Publisher, mirroring or permission-changing steps.

**Remaining before any formal admission:** obtain an independently authenticated
upstream OpenPGP signing key/fingerprint and verify each signature *against the
actual original ZIP bytes*, bind a genuine producer source/build attestation,
reconcile complete per-component NOTICE/dependency obligations, then satisfy
fresh source-specific owner/Environment/Publisher admission. Until all gates
pass, the existing production CLI must reject GET for PGroonga.
