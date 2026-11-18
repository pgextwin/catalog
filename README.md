# pgextwin catalog

[日本語](README_ja.md) | English

The [pgextwin website](https://pgextwin.github.io/website/en/) is the recommended place to find published **unofficial Windows x64 PostgreSQL extension binaries**.

This repository contains the download information used by that website. It is **not** where ZIP files are hosted. The binary packages and their release notes are on each extension's **GitHub Releases** page.

## Binary sources and review details

Users will see two provider groups: **external** (upstream/community binaries) and
**pgextwin** (including our reference-adapted and native builds). The pgextwin
CLI feed uses signed Catalog metadata. For external originals, the CLI uses
records with version-specific license evidence and byte pins.
For provenance, reference build choices, reasons to exclude a source, dependencies
and verification evidence, see [external sources and selection policy](docs/issue-112-external-windows-sources.md).

## Download packages with the Windows CLI

Windows CLI v0.3.18 lists and downloads external extensions, spatial bundles,
tools, and drivers without requiring a PostgreSQL installation. Try
`pgextwin list --category spatial` or `pgextwin download psqlodbc`.
The CLI checks the SHA-256 and exact size of each original file before saving it.

[Download guide](docs/issue-112-public-external-original-get.md) ·
[CLI releases](https://github.com/pgextwin/catalog/releases)

## What you can check

- Whether a package is published for your PostgreSQL major version.
- Direct download links and SHA-256 checksums for published ZIPs.
- Installation requirements, including preload and any separately installed executable.
- Availability of SPDX SBOMs, vulnerability reports, and signed build attestations, when included with a particular Release.

A published binary may remain available after the associated PostgreSQL version reaches end of support. Availability does not imply continued upstream support.

## Install safely

Select the ZIP for your PostgreSQL major version, verify its checksum, and follow the extension's own installation instructions. Consult the upstream project for functionality and limitations. The pgextwin project is independent of PostgreSQL, EDB and the upstream extension authors.

[English catalog](https://pgextwin.github.io/website/en/) · [日本語カタログ](https://pgextwin.github.io/website/ja/)
