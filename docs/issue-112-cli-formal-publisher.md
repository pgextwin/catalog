# Issue #112 — independent formal CLI Publisher authorization

**Nonpublishing preparation: DENY by default.** The successful Windows original-provider GET E2E is not a CLI Release approval.

## Separate authorization contract

1. In the official GitHub settings UI, the owner creates and configures the *Catalog* Environment `cli-external-get-publisher` with only `main` deployment branch, ShutenOishi as required reviewer, and administrator bypass disabled. Record the authenticated numeric Environment ID. A missing Environment must **never** be treated as an implicit approval.
2. In a separate protected PR, change `config/cli-external-get-formal-publisher-v1.json` from DENY only after verifying the actual settings. Pin `publishAuthorized=true`, the new unoccupied CLI `approvedVersion` and exact numeric `environmentId`. Do not modify v0.3.6.
3. Protected main candidate must pass native required Validate, source/attempt/run checks, actual Windows EXE SHA256, independent Sigstore provenance, license, SPDX and exact asset-contract verification. The publish job requires the dedicated Environment approval.
4. **Before any tag or Release write**, the publish job authenticates its own original attempt-1 workflow_run from the CLI release workflow and the genuine deployment approval API for this exact Run. The reviewer must match ShutenOishi's ID, the *pinned existing* Environment name and ID. An auto-created unprotected Environment has no valid owner review and fails closed.
5. Only then is the existing create-only five-asset draft, SHA256/digest readback, public byte download and Windows public smoke permitted. Never overwrite a tag or completed Release.

## Scope and non-goals

- Only pg_trickle PG18 original-provider GET with an independently verified, unexpired owner-reviewed signed pin is in scope. The pin is time-limited; publication of a capable CLI does not itself authorize or ensure a later download.
- No external ZIP mirror or redistribution. No elevation for oracle_fdw/community pgvector; those remain P3 HOLD. No third-party package installation is authorized.
- No synthetic dispatch, replay of successful runs, accidental Environment auto-creation as approval, or bypass of protected branch/required checks.
- During this preparation PR, `publishAuthorized=false`, approved version/Environment ID are null, and no CLI version, tag, Release or existing signed pin is changed.

## Completion boundary

This PR introduces and tests the independent fail-closed Publisher path only. Formal Environment setup and its authenticated ID, the later separately approved intent PR, fresh candidate Run, same-Run owner approval, create-only Release, five public assets and actual downloaded-byte smoke are distinct later conditions.
