# Issue #112 — pg_bigm PG14 exact historical formal-P1 bridge

**Scope:** One immutable `pgextwin/pg_bigm` PG14 Release row only. This private,
nonpublishing gate does not modify the ordinary P1 verifier, Promotion,
Publisher, CI, Catalog v2 record, 70-row fleet or historical-source register.

## Admission order

1. Independently hash the preserved external **new** archive (1,860,126 bytes,
   SHA256 `bc4f0ce2c43f246e2535510eb0bad34e380db15f6b57c97a831b3c42b8d37744`),
   ledger, seal and manifest against hard-coded out-of-band pins; validate all
   31 manifest members, safe bounded tar members and internally nested prior
   archive. Verify original full 16 Asset numeric IDs/names/sizes/digests and
   hash all original payloads; independently compare 15 original unchanged
   `SHA256SUMS.txt` lines with the actual 15 payload hashes.
2. Independently hash the **separate prior original PG14 evidence archive**
   (533,654 bytes, SHA256
   `4e126798ea4fa84b50c441143ff3294d675831843c3b2bb3e57ff8a2f30e9ba3`),
   compare the original byte-exact 1,856-byte receipt and require the same PG14
   ZIP/checksum bytes as the full Release gate. Reconstruct the single original
   PG14 verifier input in a private temporary directory, validate original
   immutable Catalog, Release, source and Run/attempt 1, and **rerun the merged
   historical verifier with genuine official `gh attestation verify`** against
   the SHA256-pinned, original TUF-verified Trusted Root. Both SLSA v1 and SPDX
   2.3 attestations, signed subject, original release `windows.yml` **push**,
   X.509/OIDC, upstream full SHA and successful source/Publish jobs must pass.
   The reexecuted verifier output must match the byte-pinned original receipt.
3. Only then may this *one* row report `formalP1RowsAccepted=1/70`.
   Historical source stays **0/40**, other 69 rows unadmitted, P1 **BLOCKED**,
   P2 **NO-GO**, `publicationAuthorized=false`,
   `distributionAuthorized=false`, fleet incomplete and formal distribution
   **DENY**. This outcome is not a publication/installation command.

No archive, ledger, receipt, fixture, hash-only evidence or GitHub metadata
can be treated as the result of real Sigstore cryptographic validation.
Failure or missing evidence produces exit **2** and zero accepted rows.
The authenticated HTTPS provenance and preservation of both source archives
must be reviewed. This is **not a substitute** for independently trustworthy
root acquisition or real `gh` execution.

## Offline execution

The following **seven files** must exist locally as raw original bytes:
the new all-16 archive, matching external ledger/manifest/seal, the separate
prior PG14 archive, the original PG14 receipt, and the original TUF-verified
Trusted Root. Do not substitute rendered markdown/JSON or reconstruct evidence.

```sh
python scripts/distribution_historical_p1_bridge.py \
  --historical-pg-bigm-pg14 \
  --release-archive PRIVATE/pgextwin-issue112-pgbigm-release16-resume6-20261016-evidence.tar.gz \
  --manifest PRIVATE/pgextwin-issue112-pgbigm-release16-resume6-20261016-manifest.json \
  --ledger PRIVATE/pgextwin-issue112-pgbigm-release16-resume6-20261016-ledger.json \
  --seal PRIVATE/pgextwin-issue112-pgbigm-release16-resume6-20261016-seal.json \
  --prior-pg14-archive PRIVATE/pgextwin-issue112-pgbigm-pg14-reaudit-evidence-20261016.tar.gz \
  --pg14-receipt PRIVATE/pgextwin-issue112-pgbigm-pg14-reaudit-receipt-20261016.json \
  --trusted-root PRIVATE/tuf-verified-root.jsonl
python -m unittest discover -s tests -p 'test_distribution_historical_p1_bridge.py'
```

**Current evidence status:** New archive bytes and old archive bytes are not
available in this Chat (their external pins and the new ledger/manifest/seal,
old receipt are known); therefore **no genuine bridge execution**, no 1/70
counter change and no source acceptance may be claimed. App15368 tests on
synthetic data validate rejection behaviour only.

**Never** widen this allowlist to PG15–18, other extensions, failed
plpgsql_check Run 38128142145/attempt 1 or normal Promotion requirements.
Never create/publish direct all-extension offline ZIPs; future CLI creates
that file locally. Existing individual releases and Website remain intact.
