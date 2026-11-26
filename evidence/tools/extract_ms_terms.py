#!/usr/bin/env python3
"""Deterministically extract the Microsoft VC++ v14 redistributable license
terms text designated by https://aka.ms/VCRedistLicense.

Method (owner decision A, 2026-11-26):
1. Fetch the aka.ms URL following redirects; save the full landing page HTML
   (visualstudio.microsoft.com license-terms page) byte-exact.
2. The page presents the terms through an embedded-document iframe
   (view.officeapps.live.com) whose `src` query parameter names the terms
   DOCX on visualstudio.microsoft.com. Parse that URL out of the saved page
   (first iframe whose decoded src ends in .docx).
3. Download the DOCX byte-exact.
4. Extract the body text from word/document.xml: walk the XML in document
   order; text runs (w:t) are concatenated within a paragraph (w:p); each
   paragraph becomes one line; w:tab becomes a tab; non-breaking spaces are
   normalized to plain spaces; each line is stripped; empty lines are
   dropped; lines are joined with '\n' and the output ends with one '\n'.

Outputs (into the working directory):
- ms-vc-terms-page.html          (full landing page, byte-exact)
- ms-vc-terms.docx               (the embedded terms document, byte-exact)
- ms-vc-terms-extracted.txt      (the extracted terms text)
- ms-vc-terms-capture.json       (URLs, redirect chain, byte sizes, SHA-256s)

No randomness, no timestamps inside the extracted text; re-running against
the same page/document bytes reproduces the same extracted text exactly.
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

AKA_URL = "https://aka.ms/VCRedistLicense"
W_NS = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"


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
        final_url = resp.geturl()
        status = resp.status
    return body, final_url, status, handler.chain


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def find_docx_url(page_html):
    text = page_html.decode("utf-8", errors="replace")
    for m in re.finditer(r'<iframe[^>]+src="([^"]+)"', text):
        src = m.group(1).replace("&amp;", "&")
        qs = urllib.parse.parse_qs(urllib.parse.urlsplit(src).query)
        for candidate in qs.get("src", []):
            if candidate.lower().endswith(".docx"):
                return candidate
    raise SystemExit("no embedded .docx terms document found in page")


def extract_docx_text(docx_bytes):
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
    return ("\n".join(lines) + "\n").encode("utf-8")


def main():
    page, final_url, status, chain = fetch(AKA_URL)
    open("ms-vc-terms-page.html", "wb").write(page)

    docx_url = find_docx_url(page)
    docx, docx_final, docx_status, docx_chain = fetch(docx_url)
    open("ms-vc-terms.docx", "wb").write(docx)

    extracted = extract_docx_text(docx)
    open("ms-vc-terms-extracted.txt", "wb").write(extracted)

    capture = {
        "akaUrl": AKA_URL,
        "redirectChain": chain,
        "finalUrl": final_url,
        "finalStatus": status,
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
    print(json.dumps(capture, indent=2, sort_keys=True))
    with open("ms-vc-terms-capture.json", "w", encoding="utf-8") as fh:
        json.dump(capture, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
