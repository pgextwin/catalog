# Issue #112 — mruby-file-stat inherited Ruby terms: fixed candidate only

**Status:** CANDIDATE_ONLY / PUBLIC_GET_DENY / MIRROR_DENY / RELEASE_DENY. Source-rights discovery, not producer, signing, admission or publication authorization.

## Primary-source facts

- The fixed [mruby-file-stat source](https://github.com/ksss/mruby-file-stat/blob/7d0e63a95a38b34c635b708874ec624c7c860507/src/file-stat.c) identifies the mutable `ruby/ruby/blob/trunk/file.c` as its origin. Its [README](https://github.com/ksss/mruby-file-stat/blob/7d0e63a95a38b34c635b708874ec624c7c860507/README.md) refers to that upstream source under License. The fixed gem root has no separate LICENSE file.
- The README separately links to Ruby 2.1.5 `File::Stat` documentation. For a **bounded candidate terms reference only**, Ruby tag `v2_1_5` resolves to immutable commit [`02560c6a7935543221aaed397fded3dcdf825188`](https://github.com/ruby/ruby/tree/02560c6a7935543221aaed397fded3dcdf825188). **This does NOT identify the exact Ruby revision used by mruby-file-stat or prove it was incorporated into the released Groonga/PGroonga ZIP.**
- At that fixed Ruby commit, [`file.c`](https://github.com/ruby/ruby/blob/02560c6a7935543221aaed397fded3dcdf825188/file.c) credits Yukihiro Matsumoto (1993–2007), Network Applied Communication Laboratory, Inc. (2000) and Information-technology Promotion Agency, Japan (2000). Its [`COPYING`](https://github.com/ruby/ruby/blob/02560c6a7935543221aaed397fded3dcdf825188/COPYING) offers the Ruby license terms or the two-clause [`BSDL`](https://github.com/ruby/ruby/blob/02560c6a7935543221aaed397fded3dcdf825188/BSDL). The BSDL option requires reproduction of copyright, conditions and disclaimer in binary-distribution materials.
- At the same fixed commit, [`LEGAL`](https://github.com/ruby/ruby/blob/02560c6a7935543221aaed397fded3dcdf825188/LEGAL) lists exceptions to Ruby's general terms. No literal standalone `file.c` entry was observed. This does **not** settle copied subsections, adaptations, transitive components or exceptions at any other revision.

The complete, **unaltered 1,282-byte Ruby v2.1.5 BSDL** is retained as a [candidate notice](issue-112-pgroonga-file-stat-ruby-bsd-candidate.txt). Its Git blob must equal the upstream source Git blob `a009caefea81f259e19d842356cb43ecf1710fff`; independent retrieval checks this. It is separate from the existing seven MRuby/xxHash notice candidates. **It is not delivered by the public CLI** and does not fulfil redistribution obligations by simply existing as Catalog documentation.

[Machine-readable fixed-source receipt](../evidence/issue112-pgroonga-file-stat-ruby-terms-v1.json) preserves all authorizations and acceptance flags as false.

## Remaining acceptance work

1. Identify the exact Ruby `file.c` revision adapted into the pinned mruby-file-stat source and establish its copying lineage, third-party exceptions and appropriate complete rights.
2. Authenticate the pinned mruby-file-stat input to the historical Groonga build and released PGroonga 4.1.0 binaries; the official producer used mutable `groonga-latest.zip`.
3. Resolve all other static/header/dependency notices, select license terms, and implement actual notices bound to a signed selection and atomic local batch.
4. Reuse the existing original-byte and Windows runtime proofs; source-specific authentic admission, independent signature verification, formal Publisher and public CLI E2E remain separate gates.

No code, issuer, workflow, qualification, source pin, Publisher or public CLI changes. No permission or new public ZIP is granted.

## Chronology-safe upstream cross-check (2026-11-11, nonpublishing)

A direct immutable GitHub source comparison narrows the chronological license
candidate without identifying the exact copied `file.c` revision:

- The earliest observed `ksss/mruby-file-stat` implementation of
  `src/file-stat.c` is commit
  [`bdc42c8b6d649e0148bab07568126401e7011523`](https://github.com/ksss/mruby-file-stat/commit/bdc42c8b6d649e0148bab07568126401e7011523)
  (2014-06-08 02:41:33 UTC), Git blob
  `bf99633b958fa568f1ec73d2f99325e619cd237f`. Even there, the
  comment points to mutable Ruby `trunk/file.c`; no immutable copied
  source revision is recorded.
- Ruby `v2_1_2`, commit
  [`faba7187c5e659d7a6da67ec844c4989fc74a8d5`](https://github.com/ruby/ruby/commit/faba7187c5e659d7a6da67ec844c4989fc74a8d5),
  predates that implementation (tag commit 2014-05-08). Its
  [`BSDL`](https://github.com/ruby/ruby/blob/faba7187c5e659d7a6da67ec844c4989fc74a8d5/BSDL)
  is **the exact same 1,282-byte Git blob**
  `a009caefea81f259e19d842356cb43ecf1710fff` as Ruby
  `v2_1_5` and the existing complete Catalog BSDL candidate.
  The preexisting notice text therefore existed before the first observed
  `mruby-file-stat` commit; **that establishes availability of the
  terms, not copying provenance**. The `v2_1_2` source
  [`COPYING`](https://github.com/ruby/ruby/blob/faba7187c5e659d7a6da67ec844c4989fc74a8d5/COPYING)
  Git blob is `a1f19ff99db145ed38350f195c5481ef28267649`;
  [`LEGAL`](https://github.com/ruby/ruby/blob/faba7187c5e659d7a6da67ec844c4989fc74a8d5/LEGAL)
  is `65706459cd18d5534c7b3ec2495dc736493a2847`.
  Ruby `v2_1_2/file.c` blob is
  `77facacfcf202aba80324f8aeab0011bc8d8675f`.
- Separately, Groonga's **annotated official**
  [`v16.1.3` tag](https://github.com/groonga/groonga/releases/tag/v16.1.3)
  resolves to the previously reviewed source commit
  [`9085dd417e5cd42cd8f1a367aaf24cfe45dd9f1f`](https://github.com/groonga/groonga/commit/9085dd417e5cd42cd8f1a367aaf24cfe45dd9f1f).
  The Groonga Release API reports its original source asset
  `groonga-16.1.3.zip` as 136,286,598 bytes with
  `sha256:ad892560511e5886dea2373101f0780e0a16394d30e5a20a8d3df12d7ef9e85d`
  (API-advertised digest, **not** a new independent download/re-hash).
  **Neither** the tag nor that versioned ZIP proves the contents of the
  mutable `groonga-latest.zip` fetched and deleted by PGroonga's
  official 2026-10-09 Windows build.

**Strict acceptance:** exact historical mutable input, modified-file lineage,
applicable per-file exceptions, complete notices, binary/producer binding,
and actual public companion-notice delivery are still unproven. All
`CANDIDATE_ONLY / PUBLIC_GET_DENY / MIRROR_DENY / RELEASE_DENY` gates remain
unchanged; this cross-check does not authorize a dispatch, signed cohort,
publisher or release.
