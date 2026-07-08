"""Smoke tests for the S5.0 reporting web-UI scaffold.

The dashboard is read-only; these boot the FastAPI app with ``TestClient`` (no
browser, no live socket) and assert it serves the current dataset + static
assets. DB isolation follows the repo convention: point ``db.engine`` at a temp
SQLite file (``get_session``/``init_db`` read it at call time).
"""
import json

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine, select

from finvap import audit, db
from finvap.models import (Asset, Criticality, DataSensitivity, Environment,
                           Exposure, Finding, FindingScore, Scan)


def _bind_db(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path/'t.db'}")
    SQLModel.metadata.create_all(engine)
    monkeypatch.setattr(db, "engine", engine)
    return engine


@pytest.fixture
def client(tmp_path, monkeypatch):
    engine = _bind_db(tmp_path, monkeypatch)
    with Session(engine) as s:
        a = Asset(ip_address="10.0.0.5", hostname="pay-gw", os="Linux")
        s.add(a); s.commit(); s.refresh(a)
        s.add(Scan(target="10.0.0.5", tool="gvm"))
        s.add(Finding(asset_id=a.id, tool="gvm", name="TLS 1.0 enabled",
                      severity="Medium", severity_adjusted="High",
                      cvss_base=6.5, cvss_adjusted=7.5,
                      regulatory_clauses=json.dumps(
                          [{"citation": "RMiT 10.23", "section": "Cryptography",
                            "clause_id": "10.23"}])))
        s.commit()
    from finvap.web.app import create_app
    return TestClient(create_app())


def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.text == "ok"


def test_dashboard_renders_dataset(client):
    r = client.get("/")
    assert r.status_code == 200
    body = r.text
    assert "FinVAP" in body
    assert "10.0.0.5" in body          # asset row
    assert "TLS 1.0 enabled" in body   # finding row
    assert "High" in body              # adjusted severity surfaced
    assert "RMiT 10.23" in body        # mapped clause shown
    assert ">Edit</a>" in body         # per-finding edit affordance


def test_static_htmx_served(client):
    r = client.get("/static/js/htmx.min.js")
    assert r.status_code == 200
    assert "htmx" in r.text.lower()


def test_empty_dataset_still_renders(tmp_path, monkeypatch):
    _bind_db(tmp_path, monkeypatch)
    from finvap.web.app import create_app
    r = TestClient(create_app()).get("/")
    assert r.status_code == 200
    assert "No assets yet" in r.text


# --- S5.1: finding detail (the three score layers) ---------------------------

def test_finding_detail_shows_score_layers(tmp_path, monkeypatch):
    engine = _bind_db(tmp_path, monkeypatch)
    with Session(engine) as s:
        a = Asset(ip_address="10.0.0.9", criticality="critical",
                  data_sensitivity="financial", exposure="external")
        s.add(a); s.commit(); s.refresh(a)
        f = Finding(asset_id=a.id, tool="gvm", name="Weak TLS", cve="CVE-2024-1",
                    severity="Medium", severity_adjusted="High", cvss_adjusted=7.5,
                    regulatory_clauses="RMiT 10.23, RMiT 10.49")
        s.add(f); s.commit(); s.refresh(f)
        s.add(FindingScore(finding_id=f.id, cvss_version="3.1",
                           base_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                           base_score=6.5, base_severity="Medium", source="scan",
                           adj_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                           adj_score=7.5, adj_severity="High",
                           fw_adj_score=8.5, fw_adj_severity="High"))
        s.add(FindingScore(finding_id=f.id, cvss_version="4.0",
                           base_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N",
                           base_score=6.9, base_severity="Medium", source="derived",
                           adj_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N",
                           adj_score=7.0, adj_severity="High"))
        s.commit(); fid = f.id
    from finvap.web.app import create_app
    r = TestClient(create_app()).get(f"/finding/{fid}")
    assert r.status_code == 200
    body = r.text
    assert "Weak TLS" in body
    assert "Base" in body and "Environmental" in body and "Framework-adjusted" in body
    assert "CVSS 3.1" in body and "CVSS 4.0" in body
    assert "RMiT 10.23" in body   # mapped clause surfaced
    assert "10.0.0.9" in body     # asset context


def test_finding_detail_404(client):
    assert client.get("/finding/999999").status_code == 404


# --- S5.1: audit-history browser + AI masking proof -------------------------

def test_logs_and_ai_masking_proof(tmp_path, monkeypatch):
    _bind_db(tmp_path, monkeypatch)
    audit.record("nmap.run", command="scan",
                 target="10.0.0.9", summary="ran nmap")
    audit.ai_call(stage="report", provider="ollama", model="granite3.3:8b",
                  system="You are an auditor.",
                  user_sent="Asset ASSET-1 has weak TLS.",
                  response_raw="ASSET-1 should enable TLS 1.2.",
                  placeholder_map={"ASSET-1": "10.0.0.9"},
                  response_unmasked="10.0.0.9 should enable TLS 1.2.")
    from finvap.web.app import create_app
    c = TestClient(create_app())

    lst = c.get("/logs")
    assert lst.status_code == 200
    assert "nmap.run" in lst.text
    assert "llm.call" in lst.text and ">AI<" in lst.text
    assert 'data-href="/logs/' in lst.text   # whole row is clickable

    ev = next(e for e in audit.recent() if e["action"] == "llm.call")
    det = c.get(f"/logs/{ev['id']}")
    assert det.status_code == 200
    assert "masking proof" in det.text.lower()
    assert "ASSET-1" in det.text     # placeholder shown
    assert "10.0.0.9" in det.text    # real value kept local (placeholder map)
    assert "pass" in det.text        # leak-check verdict


def test_log_detail_404(tmp_path, monkeypatch):
    _bind_db(tmp_path, monkeypatch)
    from finvap.web.app import create_app
    assert TestClient(create_app()).get("/logs/999999").status_code == 404


# --- Recompute (score + map) lives on the Setup page (/setup/recompute) --------

def test_setup_recompute_scores_and_skips_map_without_llm(tmp_path, monkeypatch):
    from finvap import settings as user_settings
    engine = _bind_db(tmp_path, monkeypatch)
    user_settings.save({"offline": True})   # no network in scoring
    with Session(engine) as s:
        a = Asset(ip_address="10.0.0.9", criticality="critical",
                  data_sensitivity="financial", exposure="external")
        s.add(a); s.commit(); s.refresh(a); aid = a.id
        s.add(Finding(asset_id=a.id, tool="gvm", name="RCE",
                      cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                      cvss_version="3.1"))
        s.commit()
    c = _app()
    body = _await_job(c, c.post("/setup/recompute", data={
        "framework": "rmit", "cvss": "3.1", "provider": "template", "model": "",
        f"t_{aid}_criticality": "critical", f"t_{aid}_data_sensitivity": "financial",
        f"t_{aid}_exposure": "external", f"t_{aid}_environment": "production"}))
    assert "Recompute complete" in body
    assert "Scored" in body and "LLM" in body   # mapping-skipped note explains why
    assert "failed" not in body.lower()
    with Session(engine) as s:                   # tags were saved too
        assert s.get(Asset, aid).criticality.value == "critical"


# --- S5.3: finding editing (human-in-the-loop overrides) ---------------------

def test_edit_text_persists(client):
    r = client.post("/finding/1/edit-text", data={
        "name": "Renamed finding", "description": "obsolete TLS accepted",
        "solution": "disable legacy TLS protocols"})
    assert r.status_code == 200
    assert "Text saved" in r.text and "Renamed finding" in r.text
    r2 = client.get("/finding/1")
    assert "Renamed finding" in r2.text and "disable legacy TLS protocols" in r2.text


def test_override_sets_flag_and_propagates(tmp_path, monkeypatch):
    engine = _bind_db(tmp_path, monkeypatch)
    with Session(engine) as s:
        a = Asset(ip_address="10.0.0.9"); s.add(a); s.commit(); s.refresh(a)
        f = Finding(asset_id=a.id, tool="gvm", name="X", severity="Low",
                    severity_adjusted="Low")
        s.add(f); s.commit(); s.refresh(f)
        s.add(FindingScore(finding_id=f.id, cvss_version="3.1", base_vector="v",
                           base_score=3.0, base_severity="Low", source="scan",
                           adj_vector="v", adj_score=3.0, adj_severity="Low"))
        s.commit(); fid = f.id
    from finvap.web.app import create_app
    c = TestClient(create_app())
    r = c.post(f"/finding/{fid}/override", data={"severity": "Critical", "score": ""})
    assert r.status_code == 200 and "Override applied" in r.text
    with Session(engine) as s:
        f = s.get(Finding, fid)
        assert f.score_overridden is True
        assert f.severity_adjusted == "Critical"
        fs = s.exec(select(FindingScore).where(FindingScore.finding_id == fid)).first()
        assert fs.fw_adj_severity == "Critical"   # override propagates to fw_adj
    # clearing lifts the flag
    r2 = c.post(f"/finding/{fid}/clear-override")
    assert r2.status_code == 200
    with Session(engine) as s:
        assert s.get(Finding, fid).score_overridden is False


def test_add_and_remove_clause(client):
    from finvap.web.app import _parse_clauses
    client.post("/finding/1/clause", data={"add_clause": "RMiT 10.99", "remove_clause": ""})
    with db.get_session() as s:
        cites = [c["citation"] for c in _parse_clauses(s.get(Finding, 1).regulatory_clauses)]
    assert "RMiT 10.99" in cites and "RMiT 10.23" in cites   # added, original kept
    client.post("/finding/1/clause", data={"add_clause": "", "remove_clause": "RMiT 10.99"})
    with db.get_session() as s:
        f = s.get(Finding, 1)
        cites = [c["citation"] for c in _parse_clauses(f.regulatory_clauses)]
        assert "RMiT 10.99" not in cites
        assert f.clauses_overridden is True


def test_override_requires_input(client):
    r = client.post("/finding/1/override", data={"severity": "", "score": ""})
    assert r.status_code == 200
    assert "Pick a severity or enter a score" in r.text


# --- S5.4: settings (engagement / run config / SLA / model discovery) --------
# The autouse conftest fixture isolates USER_CONFIG_PATH + ENGAGEMENT_PATH per test.

def _app():
    from finvap.web.app import create_app
    return TestClient(create_app())


def _await_job(client, resp, timeout=30):
    """POST responses for analysis/recompute/report return a polling job container;
    poll /progress/{id} until it finishes (HTTP 286) and return the final HTML."""
    import re
    import time
    m = re.search(r"/progress/([0-9a-f]+)", resp.text)
    assert m, f"no job id in response: {resp.text[:200]}"
    end = time.time() + timeout
    while time.time() < end:
        r = client.get(f"/progress/{m.group(1)}")
        if r.status_code == 286:
            return r.text
        time.sleep(0.03)
    raise AssertionError("job did not finish in time")


def test_report_page_has_engagement_and_sla(tmp_path, monkeypatch):
    _bind_db(tmp_path, monkeypatch)
    r = _app().get("/report")
    assert r.status_code == 200
    body = r.text
    assert "Engagement details" in body and "Remediation SLA" in body
    assert 'name="Client_Full_Name"' in body   # an engagement field
    assert 'name="sla_Critical_ext"' in body    # an SLA field


def test_engagement_save():
    from finvap import engagement
    r = _app().post("/report/engagement", data={
        "Client_Full_Name": "Acme Bank Bhd", "Client_Short_Name": "Acme",
        "Author_Name": "Jane Doe"})
    assert r.status_code == 200 and "saved" in r.text.lower()
    saved = engagement.load()
    assert saved.get("Client_Full_Name") == "Acme Bank Bhd"
    assert saved.get("Author_Name") == "Jane Doe"


def test_setup_start_validates_framework(tmp_path, monkeypatch):
    _bind_db(tmp_path, monkeypatch)
    r = _app().post("/setup/start", data={"framework": "bogus", "cvss": "3.1",
                                          "provider": "template"})
    assert r.status_code == 200 and "invalid" in r.text.lower()


def test_sla_save():
    from finvap import settings as us
    data = {}
    for sev in ("Critical", "High", "Medium", "Low"):
        data[f"sla_{sev}_ext"], data[f"sla_{sev}_int"] = "5", "10"
    r = _app().post("/report/sla", data=data)
    assert r.status_code == 200 and "saved" in r.text.lower()
    sla = us.load_sla()
    assert sla["Critical"]["ext"] == 5 and sla["Critical"]["int"] == 10


def test_model_discovery_no_network():
    # template provider needs no backend -> fast, no network call
    r = _app().get("/models?provider=template")
    assert r.status_code == 200
    assert 'id="model-select"' in r.text          # a real dropdown is rendered
    assert "__custom__" in r.text                 # with a custom-id escape hatch


# --- S5.5: report generation -------------------------------------------------
# fill_template is mocked so the route logic is tested without an LLM/LibreOffice.

def _mock_report(monkeypatch, tmp_path, filler):
    import finvap.reporting as reporting
    from finvap import config as fconfig
    monkeypatch.setattr(fconfig, "EXPORTS_DIR", tmp_path)
    monkeypatch.setattr(reporting, "resolve_template", lambda name=None: tmp_path / "tpl.docx")
    monkeypatch.setattr(reporting, "fill_template", filler)


def test_report_page_renders(tmp_path, monkeypatch):
    _bind_db(tmp_path, monkeypatch)
    r = _app().get("/report")
    assert r.status_code == 200
    assert "What will be generated" in r.text
    assert "Generate DOCX + PDF" in r.text
    assert 'name="date_assessment"' in r.text


def test_report_generate_and_download(tmp_path, monkeypatch):
    from pathlib import Path
    def fake_fill(tmpl, base, **kw):
        d = Path(f"{base}.docx"); d.write_bytes(b"PKdocx")
        p = Path(f"{base}.pdf"); p.write_bytes(b"%PDF-1.4")
        return [d, p]
    _mock_report(monkeypatch, tmp_path, fake_fill)
    _bind_db(tmp_path, monkeypatch)
    c = _app()
    body = _await_job(c, c.post("/report/generate", data={"date_assessment": "01 Jun 2026",
                                                          "date_draft": "10 Jun 2026"}))
    assert "Report ready" in body
    import re
    m = re.search(r"/report/download/(report-\d+\.docx)", body)
    assert m, "download link missing"
    dl = c.get(f"/report/download/{m.group(1)}")
    assert dl.status_code == 200 and dl.content == b"PKdocx"


def test_report_generate_degrades_when_pdf_fails(tmp_path, monkeypatch):
    from pathlib import Path
    from finvap.reporting import TemplateError
    def docx_only(tmpl, base, **kw):
        Path(f"{base}.docx").write_bytes(b"PKdocx")   # DOCX written, then PDF fails
        raise TemplateError("soffice not found")
    _mock_report(monkeypatch, tmp_path, docx_only)
    _bind_db(tmp_path, monkeypatch)
    c = _app()
    body = _await_job(c, c.post("/report/generate", data={}))
    assert "Report ready" in body and "PDF step failed" in body


def test_report_generate_error(tmp_path, monkeypatch):
    def boom(tmpl, base, **kw):
        raise RuntimeError("no LLM reachable")
    _mock_report(monkeypatch, tmp_path, boom)
    _bind_db(tmp_path, monkeypatch)
    c = _app()
    body = _await_job(c, c.post("/report/generate", data={}))
    assert "failed" in body.lower()


def test_report_download_rejects_bad_name(tmp_path, monkeypatch):
    from finvap import config as fconfig
    monkeypatch.setattr(fconfig, "EXPORTS_DIR", tmp_path)
    c = _app()
    assert c.get("/report/download/notthere.docx").status_code == 404  # missing
    (tmp_path / "evil.txt").write_text("x")
    assert c.get("/report/download/evil.txt").status_code == 404       # wrong suffix


# --- S5.5b: per-finding manual report inputs (steps/comments/screenshots) -----

def _png_bytes(w=16, h=16):
    import struct
    import zlib
    def ch(t, d):
        c = t + d
        return struct.pack(">I", len(d)) + c + struct.pack(">I", zlib.crc32(c) & 0xffffffff)
    raw = b"".join(b"\x00" + bytes((10, 120, 60)) * w for _ in range(h))
    return (b"\x89PNG\r\n\x1a\n" + ch(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
            + ch(b"IDAT", zlib.compress(raw)) + ch(b"IEND", b""))


def test_report_input_save_and_serve(tmp_path, monkeypatch):
    from finvap import config as fconfig
    monkeypatch.setattr(fconfig, "UPLOADS_DIR", tmp_path / "uploads")
    engine = _bind_db(tmp_path, monkeypatch)
    with Session(engine) as s:
        a = Asset(ip_address="10.0.0.1"); s.add(a); s.commit(); s.refresh(a)
        f = Finding(asset_id=a.id, tool="gvm", name="Weak TLS")
        s.add(f); s.commit(); s.refresh(f); fid = f.id
    png = _png_bytes()
    c = _app()
    r = c.post(f"/finding/{fid}/report-input",
               data={"steps": "Step A\nStep B", "client_comments": "noted",
                     "postverif_comments": "fixed"},
               files={"poc_screenshot": ("poc.png", png, "image/png")})
    assert r.status_code == 200 and "Report inputs saved" in r.text
    body = c.get(f"/finding/{fid}").text
    assert "Step A" in body and "noted" in body and "/uploads/finding" in body
    import re
    m = re.search(r"/uploads/(finding\d+_poc\.png)", body)
    assert m, "screenshot preview link missing"
    img = c.get(f"/uploads/{m.group(1)}")
    assert img.status_code == 200 and img.content == png


def test_report_input_remove_screenshot(tmp_path, monkeypatch):
    from finvap import config as fconfig
    from finvap.models import FindingReportInput
    monkeypatch.setattr(fconfig, "UPLOADS_DIR", tmp_path / "uploads")
    engine = _bind_db(tmp_path, monkeypatch)
    with Session(engine) as s:
        a = Asset(ip_address="10.0.0.1"); s.add(a); s.commit(); s.refresh(a)
        f = Finding(asset_id=a.id, tool="gvm", name="X"); s.add(f); s.commit(); s.refresh(f); fid = f.id
    c = _app()
    c.post(f"/finding/{fid}/report-input", data={"steps": ""},
           files={"poc_screenshot": ("poc.png", _png_bytes(), "image/png")})
    c.post(f"/finding/{fid}/report-input", data={"steps": "", "remove_poc": "on"})
    with Session(engine) as s:
        ri = s.exec(select(FindingReportInput).where(FindingReportInput.finding_id == fid)).first()
        assert ri is not None and ri.poc_screenshot is None


def test_uploads_rejects_bad_name(tmp_path, monkeypatch):
    from finvap import config as fconfig
    up = tmp_path / "uploads"; up.mkdir()
    monkeypatch.setattr(fconfig, "UPLOADS_DIR", up)
    c = _app()
    assert c.get("/uploads/nope.png").status_code == 404       # missing
    (up / "x.txt").write_text("x")
    assert c.get("/uploads/x.txt").status_code == 404          # not an image


# --- S5.6: polish (security headers, local-bind guard, AI-path auditing) -----

def test_security_headers():
    r = _app().get("/healthz")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert "default-src 'self'" in r.headers["content-security-policy"]


def test_safe_host_rejects_non_loopback(monkeypatch):
    from finvap.web.server import _safe_host
    monkeypatch.delenv("FINVAP_WEB_ALLOW_LAN", raising=False)
    assert _safe_host("0.0.0.0", None) == "127.0.0.1"     # routable -> forced loopback
    assert _safe_host("127.0.0.1", None) == "127.0.0.1"
    monkeypatch.setenv("FINVAP_WEB_ALLOW_LAN", "1")
    assert _safe_host("0.0.0.0", None) == "0.0.0.0"        # explicit override honoured


def test_setup_page_renders(tmp_path, monkeypatch):
    engine = _bind_db(tmp_path, monkeypatch)
    with Session(engine) as s:
        a = Asset(ip_address="10.0.0.5"); s.add(a); s.commit(); s.refresh(a)
        s.add(Finding(asset_id=a.id, tool="gvm", name="X")); s.commit()
    r = _app().get("/setup")
    assert r.status_code == 200
    body = r.text
    assert 'name="framework"' in body                       # a run setting
    assert 'name="t_' in body and "criticality" in body     # per-asset tag select
    assert "10.0.0.5" in body
    # Regression: the provider select must override the form's inherited
    # hx-disabled-elt="find button" — htmx 2.0.3 crashes mid-request when
    # `find` matches nothing inside the triggering element, so the model
    # field never swaps (the original "provider change does nothing" bug).
    provider_select = body.split('name="provider"')[1][:400]
    assert 'hx-disabled-elt="this"' in provider_select


def test_setup_shows_api_keys_and_tag_guide(tmp_path, monkeypatch):
    _bind_db(tmp_path, monkeypatch)
    body = _app().get("/setup").text
    # #1 cloud API-key fields (masked) + where they're stored
    assert 'name="openai_api_key"' in body and 'name="anthropic_api_key"' in body
    assert 'type="password"' in body and "finvap.secrets.json" in body
    # #2 model field is a server-rendered dropdown container, not a bare text input
    assert 'id="model-field"' in body
    # #4 per-tag "?" explainers with each choice's meaning
    assert "tag-guide" in body and "qmark" in body
    assert "Mission-critical" in body                       # a criticality explanation
    assert "regulatory event" in body                       # a data-sensitivity explanation


def test_setup_exposes_and_saves_offline_and_template(tmp_path, monkeypatch):
    """`offline` + report `template` used to be settable only via `finvap config`;
    the Setup page now carries them so the CLI can be removed without losing them."""
    from finvap import settings as user_settings
    engine = _bind_db(tmp_path, monkeypatch)
    with Session(engine) as s:
        a = Asset(ip_address="10.0.0.5"); s.add(a); s.commit(); s.refresh(a)
        s.add(Finding(asset_id=a.id, tool="gvm", name="X")); s.commit()
    c = _app()
    body = c.get("/setup").text
    assert 'name="offline"' in body and 'type="checkbox"' in body
    assert 'name="template"' in body and "VA Template.docx" in body   # bundled template offered
    # Save both, then confirm they persisted.
    _await_job(c, c.post("/setup/recompute", data={
        "framework": "rmit", "cvss": "3.1", "provider": "template", "model": "",
        "offline": "1", "template": "VA Template.docx"}))
    saved = user_settings.load()
    assert saved["offline"] is True and saved["template"] == "VA Template.docx"
    # Absent checkbox => off; unknown template is rejected up front (no job).
    _await_job(c, c.post("/setup/recompute", data={
        "framework": "rmit", "cvss": "3.1", "provider": "template", "model": ""}))
    assert user_settings.load()["offline"] is False
    r = c.post("/setup/recompute", data={
        "framework": "rmit", "cvss": "3.1", "provider": "template", "template": "nope.docx"})
    assert "Unknown report template" in r.text


def test_delete_finding_from_dashboard_row(tmp_path, monkeypatch):
    """A dashboard-row Delete removes the finding + its scores and re-renders the
    findings table in place (no full-page reload)."""
    engine = _bind_db(tmp_path, monkeypatch)
    with Session(engine) as s:
        a = Asset(ip_address="10.0.0.5"); s.add(a); s.commit(); s.refresh(a)
        f1 = Finding(asset_id=a.id, tool="gvm", name="Del-me", cvss_base=7.0)
        f2 = Finding(asset_id=a.id, tool="gvm", name="Keep-me", cvss_base=5.0)
        s.add(f1); s.add(f2); s.commit(); s.refresh(f1)
        s.add(FindingScore(finding_id=f1.id, cvss_version="3.1", base_vector="x",
                           base_score=7.0, base_severity="High", source="scan",
                           adj_vector="x", adj_score=7.0, adj_severity="High")); s.commit()
        fid = f1.id
    c = _app()
    assert "Delete</button>" in c.get("/").text                # button present on the dashboard
    r = c.post(f"/finding/{fid}/delete")
    assert r.status_code == 200
    assert "Del-me" not in r.text and "Keep-me" in r.text      # table re-rendered without it
    with Session(engine) as s:
        assert s.get(Finding, fid) is None
        assert len(s.exec(select(FindingScore)).all()) == 0    # scores cascaded


def test_delete_finding_from_detail_redirects(tmp_path, monkeypatch):
    engine = _bind_db(tmp_path, monkeypatch)
    with Session(engine) as s:
        a = Asset(ip_address="10.0.0.5"); s.add(a); s.commit(); s.refresh(a)
        f = Finding(asset_id=a.id, tool="gvm", name="Solo"); s.add(f); s.commit(); s.refresh(f)
        fid = f.id
    c = _app()
    assert "Delete finding" in c.get(f"/finding/{fid}").text    # button on the detail page
    r = c.post(f"/finding/{fid}/delete", data={"redirect": "1"})
    assert r.headers.get("hx-redirect") == "/"                 # detail page bounces to dashboard
    with Session(engine) as s:
        assert s.get(Finding, fid) is None
    assert c.post("/finding/9999/delete").status_code == 404   # missing finding


def test_setup_preloads_model_select(tmp_path, monkeypatch):
    """The model dropdown arrives already filled (server-side discovery at page
    render) — there is no on-load fetch that can strand the field on a
    'discovering models…' placeholder if the box is busy."""
    _bind_db(tmp_path, monkeypatch)
    from finvap.reporting import providers
    monkeypatch.setattr(providers, "discover_models",
                        lambda p: (["granite3.3:8b"], "1 local model(s)"))
    body = _app().get("/setup").text
    assert 'id="model-select"' in body and "granite3.3:8b" in body
    assert "discovering models…" not in body


def test_model_field_is_a_dropdown(tmp_path, monkeypatch):
    _bind_db(tmp_path, monkeypatch)
    body = _app().get("/models?provider=template").text
    assert 'id="model-select"' in body                      # a real <select>
    assert "__custom__" in body                             # with a custom-id escape hatch
    assert "(provider default)" in body


def test_models_falls_back_to_provider_suggestions(tmp_path, monkeypatch):
    """Switching provider always yields provider-specific choices: when live
    discovery can't run (no API key), the curated ids appear with a warning."""
    from finvap import config
    _bind_db(tmp_path, monkeypatch)
    monkeypatch.setattr(config, "get_api_key", lambda p: "")   # ensure keyless
    body = _app().get("/models?provider=anthropic").text
    assert "claude-opus-4-8" in body                        # curated suggestion
    assert "⚠" in body and "common ids" in body             # flagged as not live


def test_project_rename_returns_to_referring_page(tmp_path, monkeypatch):
    """The topbar menu renames from any page — the redirect lands back there."""
    _bind_db(tmp_path, monkeypatch)
    r = _app().post("/projects/nope/rename", data={"name": "X"},
                    headers={"referer": "http://127.0.0.1:1/setup"},
                    follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/setup"


def test_api_key_saved_via_setup_form(tmp_path, monkeypatch):
    from finvap import config
    _bind_db(tmp_path, monkeypatch)
    monkeypatch.setattr(config, "SECRETS_PATH", tmp_path / "secrets.json")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    c = _app()
    _await_job(c, c.post("/setup/recompute", data={
        "framework": "rmit", "cvss": "3.1", "provider": "template", "model": "",
        "openai_api_key": "sk-web-123"}))
    assert config.get_api_key("openai") == "sk-web-123"     # persisted to the secret file
    assert config.api_key_source("openai") == "saved"


def test_api_key_save_button_persists_and_triggers_discovery(tmp_path, monkeypatch):
    """The per-provider Save button stores the key immediately and tells the
    page (HX-Trigger: refresh-models) to re-discover the model list."""
    from finvap import config
    _bind_db(tmp_path, monkeypatch)
    monkeypatch.setattr(config, "SECRETS_PATH", tmp_path / "secrets.json")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    c = _app()
    r = c.post("/setup/api-key/anthropic",
               data={"anthropic_api_key": "sk-ant-9", "provider": "ollama"})
    assert r.status_code == 200
    assert config.get_api_key("anthropic") == "sk-ant-9"
    assert r.headers.get("hx-trigger") == "refresh-models"
    assert "key saved" in r.text and "chip low" in r.text    # status chip flips to "set"
    assert "Set the LLM provider above to anthropic" in r.text  # provider-mismatch hint
    assert "Clear key" in r.text                             # unset button now offered

    r = c.post("/setup/api-key/anthropic/clear", data={"provider": "ollama"})
    assert config.api_key_source("anthropic") is None        # gone from the secrets file
    assert "key cleared" in r.text and "Clear key" not in r.text
    assert r.headers.get("hx-trigger") == "refresh-models"


def test_api_key_save_button_rejects_blank_and_bad_provider(tmp_path, monkeypatch):
    from finvap import config
    _bind_db(tmp_path, monkeypatch)
    monkeypatch.setattr(config, "SECRETS_PATH", tmp_path / "secrets.json")
    c = _app()
    r = c.post("/setup/api-key/openai", data={"openai_api_key": "  "})
    assert "Paste a openai key first." in r.text
    assert c.post("/setup/api-key/gemini", data={}).status_code == 404


def test_show_all_findings(tmp_path, monkeypatch):
    engine = _bind_db(tmp_path, monkeypatch)
    with Session(engine) as s:
        a = Asset(ip_address="10.0.0.5"); s.add(a); s.commit(); s.refresh(a)
        for i in range(30):
            s.add(Finding(asset_id=a.id, tool="gvm", name=f"Finding {i:02d}", cvss_base=5.0))
        s.commit()
    c = _app()
    dash = c.get("/").text
    assert "Show all 30 findings" in dash and 'id="findings-block"' in dash
    assert dash.count('class="link" href="/finding/') == 25  # only the 25-row preview shown
    full = c.get("/findings/all").text
    assert full.count('class="link" href="/finding/') == 30  # every finding now listed (one name link each)
    assert "Show all" not in full                            # button gone once expanded


def test_setup_start_saves_and_analyzes(tmp_path, monkeypatch):
    from finvap import settings as us
    engine = _bind_db(tmp_path, monkeypatch)
    with Session(engine) as s:
        a = Asset(ip_address="10.0.0.9"); s.add(a); s.commit(); s.refresh(a); aid = a.id
        s.add(Finding(asset_id=a.id, tool="gvm", name="RCE",
                      cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                      cvss_version="3.1"))
        s.commit()
    c = _app()
    body = _await_job(c, c.post("/setup/start", data={
        "framework": "trm", "cvss": "3.1", "provider": "template", "model": "",
        f"t_{aid}_criticality": "critical", f"t_{aid}_data_sensitivity": "financial",
        f"t_{aid}_exposure": "external", f"t_{aid}_environment": "production"}))
    assert "Analysis complete" in body
    assert "Scored" in body and "LLM" in body                # map/prose skipped (template)
    assert us.load().get("framework") == "trm"               # run settings saved
    with Session(engine) as s:                               # tags saved
        a = s.get(Asset, aid)
        assert a.criticality.value == "critical" and a.exposure.value == "external"


def test_dashboard_banner_when_unanalyzed(tmp_path, monkeypatch):
    engine = _bind_db(tmp_path, monkeypatch)
    with Session(engine) as s:
        a = Asset(ip_address="10.0.0.5"); s.add(a); s.commit(); s.refresh(a)
        s.add(Finding(asset_id=a.id, tool="gvm", name="X")); s.commit()  # no FindingScore
    assert "run setup" in _app().get("/").text               # prompt to analyse


def test_projects_page_and_actions(tmp_path, monkeypatch):
    import finvap.db as _db
    from finvap import projects
    saved_engine = _db.engine
    d = tmp_path / "projects"
    monkeypatch.setattr(projects, "PROJECTS_DIR", d)
    monkeypatch.setattr(projects, "ACTIVE_FILE", d / ".active")
    try:
        a = projects.create("Client A", targets="10.0.0.1")
        b = projects.create("Client B", targets="10.0.0.2")   # B is active now
        c = _app()

        page = c.get("/projects")
        assert page.status_code == 200
        assert "Client A" in page.text and "Client B" in page.text

        c.post(f"/projects/{a}/activate", follow_redirects=False)   # switch to A
        assert projects.active() == a
        assert "Client A" in c.get("/").text                        # topbar chip

        c.post(f"/projects/{a}/rename", data={"name": "Renamed Co"}, follow_redirects=False)
        assert any(p["name"] == "Renamed Co" for p in projects.list_projects())

        c.post(f"/projects/{b}/delete", follow_redirects=False)
        assert not projects.exists(b)
    finally:
        _db.engine = saved_engine


def test_web_recompute_is_audited(tmp_path, monkeypatch):
    from finvap import audit
    from finvap import settings as us
    engine = _bind_db(tmp_path, monkeypatch)
    us.save({"provider": "template", "offline": True, "cvss": "3.1", "framework": "rmit"})
    with Session(engine) as s:
        a = Asset(ip_address="10.0.0.9"); s.add(a); s.commit(); s.refresh(a)
        s.add(Finding(asset_id=a.id, tool="gvm", name="X",
                      cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                      cvss_version="3.1"))
        s.commit()
    c = _app()
    _await_job(c, c.post("/setup/recompute", data={
        "framework": "rmit", "cvss": "3.1", "provider": "template", "model": ""}))
    # the whole web recompute groups under one audited run (LLM calls would attach here)
    assert "web.recompute" in [e["command"] for e in audit.recent()]


def test_heavy_jobs_are_serialised():
    # Two heavy jobs writing the one SQLite file at once deadlock it ("database is
    # locked"), so start() must refuse a second while one is running.
    import threading
    import time

    from finvap.web import jobs

    started, release = threading.Event(), threading.Event()

    def slow(progress):
        started.set()
        release.wait(5)
        return {"ok": True}

    jid = jobs.start(slow, "_x.html")
    assert started.wait(2) and jobs.is_running()
    with pytest.raises(jobs.JobBusy):
        jobs.start(lambda p: {}, "_y.html")
    release.set()
    for _ in range(50):                      # let the daemon thread finish + clear _active
        if not jobs.is_running():
            break
        time.sleep(0.05)
    assert not jobs.is_running()
    assert jobs.start(lambda p: {"ok": True}, "_z.html")   # idle again -> allowed
    jobs.discard(jid)


# --- #5 Risk model page (editable tag effects) -------------------------------

def test_risk_model_page_save_and_reset(tmp_path, monkeypatch):
    from finvap import settings as us
    _bind_db(tmp_path, monkeypatch)
    body = _app().get("/risk-model").text
    assert "Risk model" in body
    assert 'name="de_data_sensitivity_financial_CR"' in body      # CR/IR editable
    assert 'name="de_criticality_critical_floor"' in body         # floor kept editable
    assert 'name="de_exposure_internal_av_steps"' in body         # exposure steps
    # Save one change -> only the diff is stored; effective reflects it.
    c = _app()
    r = c.post("/risk-model", data={"de_data_sensitivity_financial_IR": "M",
                                    "de_environment_production": "M"})
    assert r.status_code == 200 and "differ from" in r.text and "●" in r.text
    assert us.load_tag_effects() == {"data_sensitivity": {"financial": {"IR": "M"}},
                                     "environment": {"production": "M"}}
    assert us.effective_tag_effects()["data_sensitivity"]["financial"]["IR"] == "M"
    assert "tag_effects.change" in [e["action"] for e in audit.recent()]  # audited (logs only)
    # Reset -> back to defaults.
    c.post("/risk-model/reset", data={})
    assert us.load_tag_effects() == {}


def test_risk_model_recompute_is_llm_free(tmp_path, monkeypatch):
    from finvap import settings as us
    engine = _bind_db(tmp_path, monkeypatch)
    us.save({"provider": "template", "offline": True, "cvss": "3.1", "framework": "rmit"})
    with Session(engine) as s:
        a = Asset(ip_address="10.0.0.9", data_sensitivity=DataSensitivity.financial,
                  criticality=Criticality.low, environment=Environment.production,
                  exposure=Exposure.internal)
        s.add(a); s.commit(); s.refresh(a)
        s.add(Finding(asset_id=a.id, tool="gvm", name="X",
                      cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                      cvss_version="3.1"))
        s.commit()
    c = _app()
    # provider=template means NO LLM available — recompute must still run (score + fw refresh).
    body = _await_job(c, c.post("/risk-model/recompute",
                                data={"de_data_sensitivity_financial_IR": "M"}))
    assert "Recompute complete" in body
    assert us.load_tag_effects()["data_sensitivity"]["financial"] == {"IR": "M"}
    with Session(engine) as s:
        assert s.exec(select(FindingScore)).first() is not None    # findings were scored


# --- CVSS calculator page (3.1 + 4.0, no 2.0) --------------------------------

def test_cvss_calculator_page(tmp_path, monkeypatch):
    _bind_db(tmp_path, monkeypatch)
    c = _app()
    t = c.get("/cvss").text
    assert "CVSS 4.0" in t and "CVSS 3.1" in t and "CVSS 2.0" not in t
    assert 'id="standalone-cvss-v4"' in t and 'id="standalone-cvss-v31"' in t
    for f in ("cvss_v4.js", "cvss_v31.js", "cvss_page.js"):
        assert c.get(f"/static/js/{f}").status_code == 200
