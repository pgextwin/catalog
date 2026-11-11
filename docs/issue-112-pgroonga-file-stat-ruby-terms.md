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
