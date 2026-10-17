# Issue #112 — Strict orafce PG14–17 cross-attempt proof

## Original evidence

This profile is strictly limited to the four original orafce PG14–17 rows at Release numeric ID 409043426, immutable packaging SHA 9f10b9039abe8c909df1ed17133481f4d64da1e4 and original Run 38062983035.

**Attempt 1 overall FAILED**. PG14, PG15, PG16 and PG17 build Jobs each succeeded; PG18 failed. Each successful Job log records two real GitHub SLSA/SPDX Attestation issuances for the exact published ZIP SHA256. No failed Run is falsely called successful.

**Attempt 2 overall SUCCEEDED**. Publish Job 114251123808 succeeded. Its original public Job log confirms five Action Artifacts downloaded and their transport SHA256 values, then constructs checksum and publishes the original GitHub Release. Each PG14–17 original upload Artifact digest agrees with a published download Artifact digest. Each original build-signed ZIP digest also agrees with the corresponding original public Release ZIP digest.

The full authenticated original publish log was saved as evidence/p1/orafce-attempt2-original-publication-log-v1.json and independently fixed to Git Blob 591f05c75cf0a5aacbedcc2cd339822080e4ad5f. A separate observed four-row identity file pins every build Job ID, ZIP numeric Asset ID and ZIP SHA256 and the transfer Artifact SHA256. Older stored full PG Windows logs are independently pinned by original Git Blob.

## Contract

scripts/distribution_p1_orafce_cross_attempt.py rechecks the exact two attempt-scoped GitHub Run and Job APIs, preserves attempt 1 failed status, confirms successful individual original PG Job and final attempt-2 publication success, independently checks full stored original log and public ZIP hashes, exact upstream immutable source and original signed PACKAGE-INFO identity, then performs genuine official gh/TUF verification of BOTH SLSA v1 and SPDX 2.3 X.509/OIDC subjects with original source SHA and original build attempt 1.

Unknown Release, other extensions, PG18, changed source, substituted artifact, missing publication, failed PG Job, signer mismatch or Sigstore failure do not PASS. No generalization of the PG14 special bridge. The original failed plpgsql_check promotion remains DENY.

## Safety / acceptance

Protected main contents:read executes this automatically; hostile PR tests do not grant signature trust. Formal P1 is **61/70** and historical source **0/40** until actual main genuine receipt proves the four candidates and a new versioned ledger and Issue record pass CI. P1 BLOCKED, P2 NO-GO, publicationAuthorized=false, distributionAuthorized=false, fleetComplete=false and distribution DENY remain unchanged. No Release, Tag, signature issuance, Publisher, Secret, Workflow Dispatch/Re-run, installation or batch ZIP creation.
