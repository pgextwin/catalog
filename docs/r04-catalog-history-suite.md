# R04 catalog history-suite dependency audit

Audited before separation at main `f97d63f1a015480f0834cd89a834cfaace197769`.

No AGENTS.md exists in this clone. Normal command is `python -m unittest discover -s tests -v`; .NET workflow builds the solution then runs the offline contract executable.

- **Keep normal:** formal ledger v2–v5 readers and their tests. `distribution_p1_batch.py` imports/validates v5; v5 validates v4, v4 validates v3, v3 validates v2. `distribution_offline_major_inventory_v1.py` also validates v5. These are live read-only policy inputs, despite their dates. Do not retire or move their validation/tamper contracts.
- **Keep normal:** `test_distribution_p1_historical_fleet.py` and `test_distribution_p1_historical_source.py`. Batch imports these source/profile verifiers, pins and inventory; `distribution_p1_orafce_cross_attempt.py` also uses historical-fleet verification. `issue112-p1-fleet-readonly.yml` actively runs the batch and these tests. Frozen evidence remains necessary to these readers.
- **History:** `test_distribution_p1_historical_source_ledger_v2.py` validates the sealed, completed source-v2 intake/artifact. Searches found no production reader/workflow consumer of its module or v2 ledger (only this test and the module's own CLI). Genesis source-v1 remains live and normal. Preserve all materials and hostile tests.
- **History:** v02/v021/v022 release contracts, archived v01/v02 public smoke policies and R7 publication contract read only `tests/fixtures/historical-workflows/` and old intent metadata. Their Actions entrypoints are already retired. R6 candidate/runtime/workflow tests instead target the live `cli-candidate.yml` / candidate reader and MUST stay normal. The R7 asset-set helper is still used by `cli-release.yml`; its current tests stay.
- **Split:** three sealed Git-tree snapshot tests in `test_distribution_p1_batch.py` are the only local historical Git-object consumer found in normal tests. Move those tests and their test-only helpers, leaving the batch's byte/signature/profile/tamper contracts normal.
- **Keep normal:** `test_retired_one_shot_cli_workflows.py` guards absence of retired publishers, plus existing nonauthorization tests throughout live P1 readers. Expand/clarify the normal nonauthorization boundary as needed; frozen fixture content assertions can move to history.
- No catalog PRE-G4 tests were found. Fixed IDs in live identity/admission/byte tests are not treated as obsolete merely because they are fixed.

