#!/usr/bin/env python3
"""Deterministically capture Microsoft's Visual Studio 2026 redistribution
list (the "Distributable List" / REDIST.TXT) and extract the two sections
that ground the VC++ runtime redistribution permission.

Method (same decision-A mechanics as extract_ms_terms.py):
1. Fetch https://aka.ms/vs/18/redistribution - the Distributable List
   location designated by section 7 of the Visual Studio 2026 license
   terms - following redirects; save the full landing page HTML
   (Microsoft Learn, "Distributable Code for Visual Studio 2026")
   byte-exact.
2. Parse the page into a flat block list (h1-h4, p, li in document order;
   block text = descendant character data with whitespace runs collapsed
   to single spaces, stripped; empty blocks dropped).
3. Extract, in order: the h1 title block; the blocks from the h2 with id
   "-distributable-code-files-for-visual-studio-2026-and-later" up to the
   next h3 (the section preamble containing the grant sentence and the
   pre-release note); and the blocks from the h3 with id
   "visual-c-runtime-files" up to the next h2/h3 (the Visual C++ Runtime
   Files section). One block per line, joined with '\n', one trailing
   '\n'.

Outputs (into the working directory):
- ms-redist-list-page.html     (full landing page, byte-exact)
- ms-redist-list-extract.txt   (the extracted sections)
- ms-redist-capture.json       (URLs, redirect chain, byte sizes, SHA-256s)

No randomness, no timestamps inside the extracted text; re-running
against the same page bytes reproduces the same extracted text exactly.
"""

import hashlib
import json
import re
import sys
import urllib.request
from html.parser import HTMLParser

START_URL = "https://aka.ms/vs/18/redistribution"
SECTION_H2_ID = "-distributable-code-files-for-visual-studio-2026-and-later"
VCRUNTIME_H3_ID = "visual-c-runtime-files"
BLOCK_TAGS = {"h1", "h2", "h3", "h4", "p", "li"}


class RecordingRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self):
        self.chain = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.chain.append({"from": req.full_url, "status": code, "to": newurl})
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url):
    handler = RecordingRedirectHandler()
    opener = urllib.request.build_opener(handler)
    req = urllib.request.Request(
        url, headers={"User-Agent": "pgextwin-evidence-capture (deterministic fetch)"}
    )
    with opener.open(req) as resp:
        body = resp.read()
        return body, resp.geturl(), resp.status, handler.chain


def sha256(data):
    return hashlib.sha256(data).hexdigest()


class BlockParser(HTMLParser):
    """Flat block list: (tag, id, text) for BLOCK_TAGS in document order.

    Character data is appended to the innermost open block only, so a
    nested list does not duplicate its items into the parent item.
    """

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.blocks = []
        self._open = []  # list of [tag, id, [text parts]]

    def handle_starttag(self, tag, attrs):
        if tag in BLOCK_TAGS:
            self._open.append([tag, dict(attrs).get("id"), []])

    def handle_data(self, data):
        if self._open:
            self._open[-1][2].append(data)

    def handle_endtag(self, tag):
        if tag in BLOCK_TAGS and self._open and self._open[-1][0] == tag:
            tag_, id_, parts = self._open.pop()
            text = re.sub(r"\s+", " ", "".join(parts)).strip()
            if text:
                self.blocks.append((tag_, id_, text))


def extract(page_bytes):
    parser = BlockParser()
    parser.feed(page_bytes.decode("utf-8"))
    blocks = parser.blocks

    def find(tag, id_):
        for i, (t, d, _text) in enumerate(blocks):
            if t == tag and d == id_:
                return i
        raise ValueError(f"anchor block not found: {tag}#{id_}")

    lines = []
    for t, _d, text in blocks:
        if t == "h1":
            lines.append(text)
            break
    i = find("h2", SECTION_H2_ID)
    while i < len(blocks) and blocks[i][0] != "h3":
        lines.append(blocks[i][2])
        i += 1
    j = find("h3", VCRUNTIME_H3_ID)
    lines.append(blocks[j][2])
    j += 1
    while j < len(blocks) and blocks[j][0] not in ("h2", "h3"):
        lines.append(blocks[j][2])
        j += 1
    return ("\n".join(lines) + "\n").encode("utf-8")


def main():
    page, final_url, status, chain = fetch(START_URL)
    open("ms-redist-list-page.html", "wb").write(page)

    extracted = extract(page)
    open("ms-redist-list-extract.txt", "wb").write(extracted)

    capture = {
        "startUrl": START_URL,
        "redirectChain": chain,
        "finalUrl": final_url,
        "finalStatus": status,
        "pageBytes": len(page),
        "pageSha256": sha256(page),
        "extractedBytes": len(extracted),
        "extractedSha256": sha256(extracted),
    }
    open("ms-redist-capture.json", "w", encoding="utf-8").write(
        json.dumps(capture, indent=2, sort_keys=True) + "\n"
    )
    print(json.dumps(capture, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
