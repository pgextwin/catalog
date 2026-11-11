# Issue #112: pg_permissions v1.4.1 immutable upstream source intake

**CANDIDATE_ONLY — no provider ZIP, newly authorized public CLI GET, mirror, signing or Release.**
Research evidence is for latest-first PostgreSQL 14–18 external expansion, not a
Windows provider-binary production receipt or a re-labeled Cybertec package.

## Authenticated upstream Git GET (2026-11-11 JST)

- Source: https://github.com/cybertec-postgresql/pg_permissions
- Upstream release: https://github.com/cybertec-postgresql/pg_permissions/releases/tag/REL_1_4_1
  published 2026-06-29, assets **none**.
- Annotated tag `REL_1_4_1`: `642eb392d89fcd37294eb8fe7126c97f628dee52`.
  GitHub tag object reports `verification.verified=true`, reason `valid`;
  the embedded PGP signature is **not** an independently verified pgextwin
  source-specific issuer or provider-binary signature.
- Peeled commit: `3360447e0668fed2b9db6a0ae1d086533781f9bd`.
- Prior annotated `REL_1_4` resolves to
  `f622556f511231521b5e30e662a93e838c6a2b2f`.
- GitHub compare `REL_1_4...REL_1_4_1`: 3 commits, 8 changed paths;
  documentation, regression workflow and Docker/test harness changed, **no
  `pg_permissions--*.sql`, `pg_permissions.control`, or `LICENSE` changes**.
- Independent immutable Git tree GETs confirmed **all nine** relevant source
  blobs identical between both commits: 7 SQL, control and LICENSE.
  Source LICENSE blob `1fd282a61d03946e180a0b82a7c82d553e175db8`;
  control blob `18ec7b614454c98b3c33b1d8e7af84167fb6e624`.
- `pg_permissions.control` says `default_version = '1.4'`.
  **Upstream package/release 1.4.1 != SQL extension version 1.4.**
  Never claim installed `CREATE EXTENSION` yields 1.4.1.

The upstream source LICENSE grants copying/distribution subject to reproduction
of its copyright and notice paragraphs in all copies. This source-level right
is not proof that any Cybertec original ZIP includes the required text or has
authenticated provider build provenance.

## Offline exact-source guard (nonpublishing)

```sh
git clone https://github.com/cybertec-postgresql/pg_permissions.git old
git -C old checkout --detach f622556f511231521b5e30e662a93e838c6a2b2f
git clone https://github.com/cybertec-postgresql/pg_permissions.git new
git -C new checkout --detach 3360447e0668fed2b9db6a0ae1d086533781f9bd
python scripts/issue112_pg_permissions_source_pins.py --old old --new new
python -m unittest discover -s tests -p 'test_issue112_pg_permissions_source_pins.py' -v
```

The guard permits no network, checks exact Git blob SHA1 for 7 SQL + control +
LICENSE separately in both local source trees, rejects missing/extra SQL,
wrong control version, symlinks, mutations and unsafe paths. CLI has no trust
override. This is reproducible **source-member equivalence only**, not
independent authentication of either remote source checkout, original provider
archive, binary provenance, rights of all packaged components, or public
distribution.

## Actual latest-first gap and explicit next admission work

Cybertec PG14–18 directory listings previously showed provider package
`pg_permissions-<PG>-public-REL_1_4-1.zip` (2025-08-04), **not**
`REL_1_4_1`. No corresponding 1.4.1 Cybertec original ZIP was established.
Do **not** silently upgrade its version label from 1.4 to 1.4.1 because the
SQL files coincide. The latest upstream release needs a separate immutable
provider/original evidence and complete license/NOTICE + dependency closure.
If building own SQL-only Windows distribution, bind source/ref, include full
attribution, perform PG14–18 real Windows acceptance, and use existing
independent signer/Publisher gates; do not copy Cybertec originals into a new
ZIP or claim their producer's signature.

**PUBLIC_GET_DENY / MIRROR_DENY / RELEASE_DENY / PUBLISH_DENY.**
