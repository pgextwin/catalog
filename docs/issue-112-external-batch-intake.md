# Issue #112 — external Windows binary repeatable review batches

**Implemented: safe, deterministic, NONPUBLISHING batch planning. Not implemented: new provider GET authorization.**

The already published CLI v0.3.7 and authorized time-limited pg_trickle PG18 direct-GET pilot stay unchanged. The existing C# signed-admission parser accepts up to **20** records, and the original ZIP staging core already supports atomic batches. The actual bottlenecks are **independent provider qualification** and the existing pg_trickle-only signed issuer, public-pin proposal, online verification, and six-hour permission.

Run the new bounded review planner (no GitHub network, download or permission):

    python scripts/issue112_external_batch_plan.py --catalog . --pg 16 --max-batch 12 --output /tmp/issue112-pg16.json

The two immutable discovery registries currently cover **203 assets**: 197 main historical and 6 portalcorp. Each provider × PostgreSQL major × format is split into batches of at most 20 with release/asset IDs, names, untrusted API digests, independently checked original digests where present, and explicit blockers. The report is created only at a new output path, reports admittedAssets=0 and all permission flags false, and **cannot be supplied as authorization to the production CLI or issuer**. Python hostile tests are automatically included in required validate.yml tests.

## Verified metadata review, 2026-11-08

| Source | Present position | Next isolated evidence batch |
| --- | --- | --- |
| Official HypoPG | 1.4.1 original ZIPs for PG14, PG15 and PG16 exist, but no GitHub API SHA256; newer 1.4.5 pgextwin build takes normal precedence. | Independently fetch/rehash exact PG16 ZIP first, then PG14/15; inspect source/version, LICENSE/NOTICE and dependencies; test original ZIP on corresponding Windows PG environments. Historical exact-version opt-in only. |
| Community portalcorp pgvector | Six historical PG16 ZIPs in discovery registry; no API SHA256; version and provenance need independent checks. | Keep separate from held andreiramani source. Independently verify bytes, compiled upstream version, rights and Windows PG16 runtime. |
| Hiraoka pg_bigm | Upstream-independent community 7z source; PG18 private functional evidence exists but a standard ZIP validator does not validate 7z. | Require a bounded 7z-specific adapter, real-byte checks, embedded notices and provenance; do not label as ZIP. |
| pg_trickle | Public CLI v0.3.7 original-provider PG18 GET succeeded. Genuine original signed pin expires 2026-11-08 21:03:43 JST. | Reuse without rerunning successful issuer or overwriting CLI. |
| Official oracle_fdw / andreiramani community pgvector | Existing source-specific P3 holds; all historical registry records remain denied. | No promotion, issuer, or publisher; reconsider only by explicit scope reprioritization. |

The original two registries do not include Hiraoka and pg_trickle additional discovery observations. Discovery and GitHub API digest alone do not authenticate original ZIP bytes.

## Next protected implementation units

1. Collect original bytes, SHA256/size, ZIP/7z structural and Windows PG functional evidence for the independently prioritized sources. Keep actual original bytes private and never mirror or release them.
2. Add **reviewed, immutable, exact-asset cohort declarations**, then generalize the genuine owner-dispatched Build issuer to validate 1–20 qualifying assets **once per owner-approved same-Run Environment**, using the current App, OIDC/Sigstore and distinct independent verifier. Never infer permission from this planner or candidate registry. Maintain separate P3 exclusions.
3. Generalize immutable Catalog pin storage and its authenticated validator + Windows public EXE E2E to batch records. The existing .NET transport and atomic staging should be reused; release a changed CLI only after a separate formal Publisher approval and create-only process. Run protected PR CI, protected merge, original postmerge, live Windows SHA256 and Website Japanese/English smoke.
4. Address short expiry by designing a **separately signed, online fail-closed, anti-rollback revocation/status mechanism**, checked before every original GET, before considering a 7-day authorization. The C# 30-day parsing upper bound is not consent for longer issuance. Simply changing the hard-coded six-hour bounds would create a revocation gap; current expiry remains enforced until safely replaced.

This completed change is the nonpublishing review-planning unit only. It does not grant an external download, attest a source, approve license terms, create a Release, or imply that postmerge/publisher gates are complete.
