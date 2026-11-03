# pgextwin catalog

[日本語](README_ja.md) | English

The [pgextwin website](https://pgextwin.github.io/website/en/) is the recommended place to find published **unofficial Windows x64 PostgreSQL extension binaries**.

This repository contains the download information used by that website. It is **not** where ZIP files are hosted. The binary packages and their release notes are on each extension's **GitHub Releases** page.

## Binary sources and review details

Users will see two provider groups: **external** (upstream/community binaries) and
**pgextwin** (including our reference-adapted and native builds). Only independently
verified and authorized downloads are offered as available. Historical/unverified
external discoveries do **not** become downloadable merely by being indexed.
For provenance, reference build choices, reasons to exclude a source, dependencies
and verification evidence, see [external sources and selection policy](docs/issue-112-external-windows-sources.md).

## What you can check

- Whether a package is published for your PostgreSQL major version.
- Direct download links and SHA-256 checksums for published ZIPs.
- Installation requirements, including preload and any separately installed executable.
- Availability of SPDX SBOMs, vulnerability reports, and signed build attestations, when included with a particular Release.

A published binary may remain available after the associated PostgreSQL version reaches end of support. Availability does not imply continued upstream support.

## Install safely

Select the ZIP for your PostgreSQL major version, verify its checksum, and follow the extension's own installation instructions. Consult the upstream project for functionality and limitations. The pgextwin project is independent of PostgreSQL, EDB and the upstream extension authors.

[English catalog](https://pgextwin.github.io/website/en/) · [日本語カタログ](https://pgextwin.github.io/website/ja/)
