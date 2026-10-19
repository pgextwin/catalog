# CLI R6 candidate boundary (Issue #112)

The existing `.NET 10` single-file `pgextwin.exe` is currently exercised only within a nonpublishing Windows PR smoke job. A CLI distribution candidate must independently bind its original executable SHA256, byte size, exact source commit, observed SDK/runtime, and Windows smoke result. Neither a checksum in an unsigned artifact nor a passing Windows smoke test grants provenance, code-signing, installation, or release authorization.

Approval remains denied until independently validated provenance, an approved signing channel, and release authorization are present. R3–R5 offline ZIP and install --apply are excluded from the v0.1 preview.
