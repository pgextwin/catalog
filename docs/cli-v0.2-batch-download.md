## v0.2.0-preview.1: all selected extension ZIPs in one operation

Use `pgextwin download-all` to retrieve all **14 original release ZIP files for one PostgreSQL major**, or up to **70 original ZIP files across PG14–18** with `--pg all`. All ZIP bytes are retained unchanged, one subfolder per PG major. The command never extracts files, overwrites existing outputs, or installs anything.

```powershell
New-Item -ItemType Directory -Force C:\pgextwin-downloads
.\pgextwin.exe download-all --pg 18 --catalog-dir C:\approved\catalog `
  --policy C:\approved\policy.json --policy-sha256 EXTERNALLY_APPROVED_64_HEX `
  --output C:\pgextwin-downloads
# For all five PostgreSQL majors, replace --pg 18 with --pg all.
```

The local Catalog snapshot and separately approved P1 policy (including an out-of-band SHA256) must already exist. Reusing a SHA from the same untrusted Catalog **does not authenticate the policy**. The existing strict release downloader checks numeric repository/Release/asset IDs, immutable asset digests and actual downloaded SHA256. The result is `INTEGRITY_ONLY`, **not signature-verified**. It produces `DOWNLOAD-INFO.json` explicitly denying installation/publication/distribution rights. If any selected download or hash validation fails, the transaction removes the temporary output and **does not expose a partial completed batch**. The output folder must not already exist.

This is a **batch of original ZIP files**, not one enclosing signed offline distribution ZIP, which remains a separate and later feature. No `install --apply`, privilege escalation, background services, registry changes, unverified release signing or modification of any existing extension Release.
