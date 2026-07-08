"""Standalone DOCX refresher / PDF exporter that **updates fields and the TOC** first.

Run as a script by a LibreOffice-UNO-capable Python (often the system
`/usr/bin/python3`, not the venv):

    python _soffice_convert.py in.docx out.pdf   # refresh the DOCX in place + write the PDF
    python _soffice_convert.py in.docx -          # refresh the DOCX in place only (no PDF)

``soffice --headless --convert-to pdf`` does *not* update a document's
table-of-contents index, so a filled template's TOC would render stale/with
unresolved placeholders. This drives LibreOffice over the UNO bridge to load the
doc, ``refresh()`` fields and ``update()`` every index, save the refreshed DOCX
back, then (optionally) export the PDF — so both artifacts have a correct TOC.

Dependency-free apart from the ``uno`` module that ships with LibreOffice — it
must import under whichever interpreter runs it, so keep it stdlib-only.
"""
import os
import socket
import subprocess
import sys
import tempfile
import time

import uno
from com.sun.star.beans import PropertyValue


def _prop(name, value):
    p = PropertyValue()
    p.Name = name
    p.Value = value
    return p


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def convert(docx: str, pdf: str | None) -> None:
    port = _free_port()
    with tempfile.TemporaryDirectory(prefix="finvap_lo_") as profile:
        proc = subprocess.Popen([
            "soffice", "--headless", "--invisible", "--nodefault", "--norestore",
            "--nologo", f"-env:UserInstallation=file://{profile}",
            f"--accept=socket,host=127.0.0.1,port={port};urp;StarOffice.ComponentContext",
        ])
        try:
            local = uno.getComponentContext()
            resolver = local.ServiceManager.createInstanceWithContext(
                "com.sun.star.bridge.UnoUrlResolver", local)
            ctx = None
            for _ in range(80):  # up to ~40s for first cold start
                try:
                    ctx = resolver.resolve(
                        f"uno:socket,host=127.0.0.1,port={port};urp;"
                        "StarOffice.ComponentContext")
                    break
                except Exception:
                    time.sleep(0.5)
            if ctx is None:
                raise SystemExit("could not connect to LibreOffice")
            smgr = ctx.ServiceManager
            desktop = smgr.createInstanceWithContext("com.sun.star.frame.Desktop", ctx)
            in_url = uno.systemPathToFileUrl(os.path.abspath(docx))
            doc = desktop.loadComponentFromURL(in_url, "_blank", 0, (_prop("Hidden", True),))
            try:
                doc.refresh()
                idxs = doc.getDocumentIndexes()
                for i in range(idxs.getCount()):
                    idxs.getByIndex(i).update()
            except Exception as e:  # keep going — a stale TOC beats a failed refresh
                sys.stderr.write(f"index update warning: {e}\n")
            # Save the refreshed DOCX back so its TOC is correct too, then the PDF.
            doc.storeToURL(in_url, (_prop("FilterName", "MS Word 2007 XML"),
                                    _prop("Overwrite", True)))
            if pdf and pdf not in ("-", ""):
                out_url = uno.systemPathToFileUrl(os.path.abspath(pdf))
                doc.storeToURL(out_url, (_prop("FilterName", "writer_pdf_Export"),
                                         _prop("Overwrite", True)))
            doc.close(False)
            try:
                desktop.terminate()
            except Exception:
                pass
        finally:
            try:
                proc.wait(timeout=30)
            except Exception:
                proc.terminate()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: _soffice_convert.py <in.docx> <out.pdf|->")
    convert(sys.argv[1], sys.argv[2])
