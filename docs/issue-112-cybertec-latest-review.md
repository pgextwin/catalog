# Issue #112 — Cybertec observed-latest and exact-label candidate review (nonpublishing)

**CANDIDATE_ONLY / PUBLIC_GET_DENY / MIRROR_DENY / RELEASE_DENY.** This is a bounded, reusable selection layer for existing Cybertec metadata only. It cannot authorize an external original ZIP, sign a Catalog admission, or alter the production `download-all` command.

## Reuse, not a second source adapter

`issue112_cybertec_latest_review.py` calls the existing canonical index-only `issue112_cybertec_windows_index.fetch_index` and `collect` functions. The observer accepts PG14–18 canonical HTTPS directory indexes, checks unsafe/duplicate links, and leaves all ABI, original bytes, provenance, NOTICE and public-use gates false. This additional selector reads the resulting untrusted receipts, checks **every candidate** for exact origin, PG, filename and denied fields before filtering, then groups by extension and PostgreSQL major.

```bash
python scripts/issue112_cybertec_latest_review.py --pg 16 --latest-observed
python scripts/issue112_cybertec_latest_review.py --pg 17 --extension pg_partman --latest-observed
python scripts/issue112_cybertec_latest_review.py --pg 16 --extension pg_partman --label v5.4.3-1
```

- `--latest-observed` chooses the greatest **numeric provider packaging label observed in that particular index** for each extension × PG major. It is **not an upstream-version assertion**. Unparseable labels fail that group's latest selection explicitly; no arbitrary lexicographic winner is chosen. Candidate duplicates and unexpected trust escalation fail closed before any selector is applied.
- `--label` matches an **exact provider packaging label** for a specified extension. It is intentionally distinct from the user-facing authenticated CLI `--version`, which names a verified extension version.
- The original PG major, exact provider filename, and URL remain visible per row; no cross-major compatibility or fallback is inferred. An absent version or PG major is an empty/denied selection, not a fabricated file.
- No ZIP, installer or Windows binary is downloaded or mirrored; there is no network operation beyond the previously existing canonical directory-index GET. No signed feed, source admission, publishing environment, CLI release or Website data changes.

## Security checks and next acceptance gate

The existing protected PR `Validate catalog` tests all Python unit tests. New offline adversarial tests cover numeric ordering, exact-label selection, ambiguous/unparseable labels, tampered **unselected** candidates, duplicate assets, incorrect PG-encoded filenames, forged URLs and permission escalation. The output retains explicit `latestUpstreamVersionVerified=false`, `communityPostgresqlAbiVerified=false`, `originalBytesVerified=false`, `independentSignedAdmission=false`, `publicGetAuthorized=false`, `mirrorAuthorized=false`, `releaseAuthorized=false`, `publisherAuthorized=false`.

Actual latest-release identification, independent original-byte SHA256, Windows EDB/PG ABI, component licenses/NOTICE, exact producer provenance and genuine source-specific signed admission are independent prerequisites for adding any Cybertec ZIP to a public `download-all --source external` cohort. Cybertec PGEE filenames alone must not be used as compatibility or producer attestations. The production signed GET-only path and its accepted 11 original ZIPs remain unchanged.
