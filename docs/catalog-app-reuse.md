# Existing Catalog App: proposal and protected merge

The already-installed `pgextwin-catalog-proposer` App (installation 170516730)
is the dedicated Catalog principal for proposal and future protected merging.
Both jobs request separate short-lived tokens restricted to `pgextwin/catalog`
(repository 1405939279), with contents/write and pull_requests/write only.
No new App, Secret, installation permission, or branch-protection exception is
needed. This Catalog App is separate from the Windows signer and the formal
Release Publisher. Proposal and Catalog merge use the same Catalog principal;
this is not an independent-reviewer claim.

The previous merge workflow referred to unconfigured `CATALOG_MERGE_APP_*`
credentials. It now reuses the existing `CATALOG_PROPOSER_APP_*` names. Before
merging, trusted main code verifies the pinned token action's App slug and
installation ID, plus the live installation token's exact one-repository scope.
All Run, Check, PR and policy reads use the independent read credential. The
write token is reserved for installation-scope inspection and protected merge.
The public byte/Sigstore verifier still receives only the read token.

The nonpublishing proof runs after successful original main/push Validate,
behind the existing proposer opt-in. It verifies current protected main and
the scoped installation token, revokes it, and requires actual HTTP401 from
that same token. The evidence records requested WRITE scopes, not a performed
repository write or a proven protected merge. It never modifies a record,
tag, Release, source policy, or runtime variable.

**Merge remains disabled.** Central `manual-release-downstream.json`, local
`verified-release-auto-merge.json`, and `PGEXTWIN_CATALOG_AUTOMERGE_ENABLED`
must separately agree before the merge job can act. Existing exact-head native
App15368 checks, genuine signed public Release verification, scoped App checks,
expected-head squash, first-intake path restrictions and branch protection are
unchanged. The read-only scope proof cannot satisfy these publication gates.

## Protected local policy activation

`validate_local_policy` validates either explicit boolean deployment state with
the same pinned Catalog/proposer/workflow identity. It returns no merge or
publication authority. `verify_policy` still requires local `enabled=true` plus
the complete matching central declaration, and the workflow separately requires
`PGEXTWIN_CATALOG_AUTOMERGE_ENABLED=true`, a scoped Catalog App token, exact-head
App15368 checks and fresh independent public signed-asset verification.

Required tests validate the actual deployment file and preserve the old disabled
declaration in `tests/fixtures/catalog-auto-merge-disabled.json`; they no longer
require the live policy to remain permanently disabled. This repair leaves the
live local configuration unchanged. An authorized future protected activation
can pass the same tests without weakening disabled-state or malformed-policy
rejection. This parser is not a Release authorization or an implicit opt-in.
