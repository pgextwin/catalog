# Issue #112 — fixed MRuby source terms and supplemental-notice preparation

Status: CANDIDATE_ONLY / PUBLIC_GET_DENY / MIRROR_DENY / RELEASE_DENY.
This closes a bounded source-text review and prepares seven complete notice
texts. It does not close legal, historical-input, runtime or publication gates.

## Source LEGAL is different from generated LEGAL

Groonga source-review candidate `9085dd417e5cd42cd8f1a367aaf24cfe45dd9f1f`
records MRuby gitlink `ae17b1130f8413052380bdb0fbde26bdd46b28e3`.
Its fixed upstream `LEGAL` is 2,592 bytes, Git blob
`9697d5747e07f870089b2318a57f8de24eda0a3d`. This is a different document
from the original ZIP's generated 3,502-byte `share/groonga/mruby/LEGAL`.
The latter lists 31 gem declarations; the former contains source-specific
exceptions and full terms. Neither can replace the other.

| Fixed candidate source | Concrete source-text finding |
| --- | --- |
| MRuby root LEGAL | `src/string.c` string-search code: Wojciech Muła copyright 2008–2016 and BSD-2-Clause body; floating-point formatting: Dave Hylands public-domain statement; Windows directory code: Kevlin Henney additional terms. These exceptions extend beyond gem license labels. |
| mruby-dir README License section | Internet Initiative Japan 2012 MIT text plus complete Kevlin Henney 1997/2003/2012 permission and disclaimer. Windows HAL source says it derives from Henney's implementation. Root LEGAL still names the older directory-source path; do not assume path equality or historical binary linkage. |
| mruby-compiler LICENSE | Separate HASUMI Hitoshi 2024 MIT notice. The packaged generated compiler declaration names MRuby and PicoRuby developers, which is not the full source notice. |
| mruby-file-stat source | `src/file-stat.c` itself identifies Ruby `trunk/file.c` as its origin. The inherited-source question is confirmed in code, not just README; exact Ruby revision and applicable complete terms remain unresolved. |

All nine retrieved primary-source files were independently checked against
Git's length-prefixed blob SHA1; SHA256 and immutable commit URLs are in
[the receipt](../evidence/issue112-pgroonga-source-terms-review.json).
The Groonga candidate gitlink is **not** proof of the historical mutable
`groonga-latest.zip` used by official PGroonga Windows Run 37872644159.

## Original-byte comparison and concrete notice materials

Reuse the already available official PG18 original; its complete SHA256 is
`3ccbfaf771ec7a0edf61dabe0eb60188dcc22feff8449a7e96afdb87641630ab`,
53,826,667 bytes. The local original's CRC passes. No new remote ZIP GET,
Windows SQL run, signing or successful workflow rerun was performed.

Compare complete source notice texts and individual terms blocks with every
bounded eligible nonbinary original member, including embedded substrings:
522 members at most 512 KiB each, of which 513 strictly decode as UTF-8.
Compare both CRLF-normalized bytes and whitespace-normalized text, preserving
case and punctuation. The receipt states exact scope and results; a missing
substring does **not** exclude semantically equivalent wording, text inside
excluded/oversized/binary members, or another lawful means of notice delivery.
This scan covers PG18 only; previous five-major document equality is separate
evidence and is not a fresh scan of the other four originals.

[The supplemental-notice candidate](issue-112-pgroonga-supplemental-notices-candidate.txt)
contains seven complete fixed source texts or License sections: MRuby root
LEGAL, mruby-dir, mruby-compiler, pp, tsort, slop, and xxHash 0.8.3. Original
copyright, conditions and disclaimers are preserved. Its exact byte length and
SHA256 are recorded in the receipt. This file is preparatory documentation;
the public CLI does not deliver it, no upstream ZIP is modified, and it is not
an assertion that those exact source revisions produced the original binaries.

The remaining concrete work is to authenticate historical inputs (or obtain
new pinned producer inputs), settle file-stat inherited terms and remaining
static/header/component obligations, and implement reviewed delivery of all
required notices as actual distribution materials. A future companion-notice
delivery must be hash-bound to the signed original selection and atomic local
batch; documentation in this repository alone does not demonstrate delivery.
Only then may the existing authentic issuer, independent verification,
source-specific admission and formal Publisher gates be considered.

New publicly admitted ZIPs: **0**. Existing admissions and CLI behavior unchanged.
