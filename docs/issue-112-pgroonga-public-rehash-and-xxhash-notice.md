# Issue #112: independent PGroonga 4.1.0 public release rehash and xxHash license candidate (nonpublishing)

Scope: official PGroonga 4.1.0 Windows ZIPs for PostgreSQL 14–18, Groonga 16.1.3 source and xxHash 0.8.3 binary-distribution notice. No change to signing, admission policy, qualified cohort, public CLI, mirror, Website or Publisher.

## Groonga 16.1.3 exact candidate source metadata

Official Groonga v16.1.3 Release: https://github.com/groonga/groonga/releases/tag/v16.1.3 (published 2026-10-08 06:43:30 UTC).

- groonga-16.1.3.tar.gz: Release asset ID 620990606; 110,532,722 bytes; SHA256 61e1c8f1671e22d7bf4cd8c35002b9674d29ba82ae2cbe6835d73d3a45af202b.
- Public URL: https://github.com/groonga/groonga/releases/download/v16.1.3/groonga-16.1.3.tar.gz
- Separate groonga-16.1.3.zip: 136,286,598 bytes; SHA256 ad892560511e5886dea2373101f0780e0a16394d30e5a20a8d3df12d7ef9e85d.

The official PGroonga 4.1.0 Windows Run 37872644159 fetched mutable groonga-latest.zip on 2026-10-09 without recording the downloaded SHA256. A rehash of either fixed Groonga v16.1.3 source archive does not prove that exact source input was fetched by that historical job. The version.h marker is insufficient as source-to-binary attestation.

The new read-only workflow independently GETs the official Groonga tarball and each of the five official PGroonga Release ZIP URLs, checks streamed bytes and SHA256 against fixed official Release API digests, and reuses the existing exact ZIP rights/CRC auditor for member-level checks. These are new checks, distinct from the already verified historical Actions artifact-to-Release digest correlation: https://github.com/pgextwin/build/issues/112#issuecomment-6784222618. A successful rehash does not grant independent Sigstore producer provenance, rights clearance, a qualified cohort or publication authorization.

## xxHash BSD-2-Clause NOTICE obligation

Tagged PGroonga xxhash.wrap pins xxHash v0.8.3 with source SHA256 aae608dfe8213dfd05d909a57718ef82f30722c392344583d3f39050c7f29a80. Original Windows Meson jobs build libxxhash.dll and xxhsum.exe using 0.8.3. The historical PGroonga release ZIPs contain both binaries but no xxHash/Yann Collet attribution in the 20 observed license/NOTICE/COPYING-named files.

The upstream original author LICENSE at https://github.com/Cyan4973/xxHash/blob/v0.8.3/LICENSE states BSD-2-Clause, copyright Yann Collet, and requires preservation of copyright, license conditions and disclaimer with binary redistribution. The text below is captured for an independently authorized future distribution; this internal document DOES NOT add it to any official upstream ZIP or remediate the packaged notice gap.

xxHash Library
Copyright (c) 2012-2021 Yann Collet
All rights reserved.

BSD 2-Clause License (https://www.opensource.org/licenses/bsd-license.php)

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice, this
  list of conditions and the following disclaimer in the documentation and/or
  other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

Other static and bundled dependencies' rights also remain unverified. Before a separate independently authorized distribution, ensure its *actual distribution materials* satisfy all notices and exact source, dependency and issuer gates.

Decision: CANDIDATE_ONLY / PUBLIC_GET_DENY / MIRROR_DENY / RELEASE_DENY.
