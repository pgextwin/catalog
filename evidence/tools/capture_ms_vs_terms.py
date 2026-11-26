#!/usr/bin/env python3
"""Deterministically capture the Visual Studio 2026 license terms
(Enterprise / Professional) and extract section 7, DISTRIBUTABLE CODE -
the terms the Visual Studio redistribution list is "subject to".

Method (same decision-A mechanics as extract_ms_terms.py):
1. Fetch the canonical terms page
   https://visualstudio.microsoft.com/license-terms/vs2026-ga-pro-enterprise/
   (linked from the license-terms index that https://aka.ms/VisualStudioLicenses
   designates); save the full page HTML byte-exact.
2. The page presents the terms through an embedded-document iframe
   (view.officeapps.live.com) whose `src` query parameter names the terms
   DOCX on visualstudio.microsoft.com. Parse that URL out of the saved
   page (first iframe whose decoded src ends in .docx) and download the
   DOCX byte-exact.
3. Extract the DOCX body text with the same paragraph algorithm as
   extract_ms_terms.py (word/document.xml paragraphs in document order;
   w:t concatenated within a paragraph; w:tab -> tab; NBSP -> space; each
   line stripped; empty lines dropped).
4. Slice the extract: the identity header (paragraphs from the start up
   to and including the one starting "Last Updated"), then section 7 -
   from the paragraph starting "DISTRIBUTABLE CODE." up to (excluding)
   the next all-caps section heading paragraph. Lines joined with '\n',
   one trailing '\n'.

Known fidelity limit (same as the decision-A EULA extraction): automatic
numbering from word/numbering.xml is not rendered, so the section's
lettered sub-paragraph markers (a./b./c.) do not appear in the extract;
the paragraph wording is complete.

Outputs (into the working directory):
- ms-vs-terms-page.html        (full landing page, byte-exact)
- ms-vs-terms.docx             (the embedded terms document, byte-exact)
- ms-vs-terms-extract.txt      (identity header + section 7)
- ms-vs-terms-capture.json     (URLs, redirect chains, sizes, SHA-256s)

No randomness, no timestamps inside the extracted text; re-running
against the same page/document bytes reproduces the same extract exactly.
"""

import hashlib
import io
import json
import re
import sys
import urllib.parse
import urllib.request
import zipfile
from xml.etree import ElementTree as ET

PAGE_URL = "https://visualstudio.microsoft.com/license-terms/vs2026-ga-pro-enterprise/"
W_NS = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
SECTION_START = "DISTRIBUTABLE CODE."
CAPS_HEADING = re.compile(r"^[A-Z0-9 ,&()\-]+\.$")


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


def find_docx_url(page_bytes):
    html = page_bytes.decode("utf-8", errors="replace")
    for match in re.finditer(r'<iframe[^>]+src="([^"]+)"', html):
        src = urllib.parse.unquote(match.group(1))
        inner = urllib.parse.parse_qs(urllib.parse.urlsplit(src).query).get("src", [src])[0]
        if inner.lower().endswith(".docx"):
            return inner
    raise ValueError("no embedded .docx iframe found on the terms page")


def extract_docx_lines(docx_bytes):
    with zipfile.ZipFile(io.BytesIO(docx_bytes)) as zf:
        xml = zf.read("word/document.xml")
    root = ET.fromstring(xml)
    lines = []
    for para in root.iter(W_NS + "p"):
        parts = []
        for node in para.iter():
            if node.tag == W_NS + "t":
                parts.append(node.text or "")
            elif node.tag == W_NS + "tab":
                parts.append("\t")
            elif node.tag in (W_NS + "br", W_NS + "cr"):
                parts.append("\n")
        line = "".join(parts).replace(" ", " ").strip()
        if line:
            lines.append(line)
    return lines


def slice_extract(lines):
    header = []
    for line in lines:
        header.append(line)
        if line.startswith("Last Updated"):
            break
    else:
        raise ValueError("identity header not found (no 'Last Updated' paragraph)")
    start = next(i for i, line in enumerate(lines) if line.startswith(SECTION_START))
    section = []
    for line in lines[start:]:
        if section and CAPS_HEADING.match(line):
            break
        section.append(line)
    return ("\n".join(header + section) + "\n").encode("utf-8")


def main():
    page, final_url, status, chain = fetch(PAGE_URL)
    open("ms-vs-terms-page.html", "wb").write(page)

    docx_url = find_docx_url(page)
    docx, docx_final, docx_status, docx_chain = fetch(docx_url)
    open("ms-vs-terms.docx", "wb").write(docx)

    extracted = slice_extract(extract_docx_lines(docx))
    open("ms-vs-terms-extract.txt", "wb").write(extracted)

    capture = {
        "pageUrl": PAGE_URL,
        "pageRedirectChain": chain,
        "pageFinalUrl": final_url,
        "pageFinalStatus": status,
        "pageBytes": len(page),
        "pageSha256": sha256(page),
        "docxUrl": docx_url,
        "docxRedirectChain": docx_chain,
        "docxFinalUrl": docx_final,
        "docxFinalStatus": docx_status,
        "docxBytes": len(docx),
        "docxSha256": sha256(docx),
        "extractedBytes": len(extracted),
        "extractedSha256": sha256(extracted),
    }
    open("ms-vs-terms-capture.json", "w", encoding="utf-8").write(
        json.dumps(capture, indent=2, sort_keys=True) + "\n"
    )
    print(json.dumps(capture, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
