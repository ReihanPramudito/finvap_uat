"""The FastAPI app for the FinVAP reporting UI.

Read-only views (S5.0 scaffold + S5.1): a dashboard of the current dataset, a
per-finding detail page surfacing the base / environmental / framework-adjusted
score layers, and an audit-history browser over the S1 trail. Reuses
``finvap.db`` + ``finvap.models`` + ``finvap.audit`` directly — no business
logic lives here. Later increments add tagging (S5.2), finding edits (S5.3),
settings/engagement (S5.4) and report generation (S5.5).
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, select

from .. import audit, config, db, engagement
from .. import settings as user_settings
from ..config import DB_PATH
from ..models import (Asset, Criticality, DataSensitivity, Environment,
                      Exposure, Finding, FindingReportInput, FindingScore, Scan)

_IMG_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".webp"}

# Valid values for the choice-typed run settings (framework/cvss/provider).
_CHOICES = {k["key"]: set(k["choices"]) for k in user_settings.KEYS if k.get("type") == "choice"}

# The four business-context tags that drive the risk score.
TAG_FIELDS = [
    ("criticality", "Criticality", Criticality),
    ("data_sensitivity", "Data sensitivity", DataSensitivity),
    ("exposure", "Exposure", Exposure),
    ("environment", "Environment", Environment),
]
TAG_ENUM = {field: enum for field, _, enum in TAG_FIELDS}
TAG_FIELD_NAMES = [field for field, _, _ in TAG_FIELDS]
TAG_LABELS = {field: label for field, label, _ in TAG_FIELDS}
TAG_OPTIONS = {field: [e.value for e in enum] for field, _, enum in TAG_FIELDS}

# Plain-English meaning of each tag choice + the CVSS environmental effect it
# drives (mirrors the tables in risk/metrics.py, grounded in FIPS 199 / SP 800-60).
# Shown behind the (?) on each tag so the operator knows what they're picking.
TAG_OPTION_HELP = {
    "criticality": {
        "low": "Non-essential host — an outage is a minor inconvenience. Availability requirement AR:Low.",
        "medium": "Supporting system — downtime is disruptive but tolerable. AR:Medium and a Medium CR/IR floor.",
        "high": "Important business system — downtime hurts operations. AR:High and a High CR/IR floor.",
        "critical": "Mission-critical — downtime halts the business or breaches obligations. AR:High and a High CR/IR floor.",
    },
    "data_sensitivity": {
        "public": "Only public / non-sensitive data. Confidentiality & Integrity requirements CR:Low / IR:Low.",
        "internal": "Internal-use data, not for release. CR:Low / IR:Medium.",
        "confidential": "Sensitive business data (contracts, IP). CR:Medium / IR:Medium.",
        "pii": "Personal data — privacy / PDPA exposure on breach. CR:High / IR:Medium.",
        "financial": "Financial / payment data (cardholder, account). CR:High / IR:High — a breach is a regulatory event.",
    },
    "exposure": {
        "internal": "Reachable only from inside the network — Attack Vector stepped down one level from base (harder to reach).",
        "external": "Internet-facing / reachable by untrusted networks — Attack Vector kept at the base worst case.",
    },
    "environment": {
        "production": "Live system serving real users/data — no cap; the full requirements above apply.",
        "staging": "Pre-production mirror — requirements capped at Medium.",
        "uat": "User-acceptance testing — requirements capped at Medium.",
        "development": "Dev/test box with no real data — requirements capped at Low.",
    },
}

WEB_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = WEB_DIR / "templates"
STATIC_DIR = WEB_DIR / "static"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def _active_project():
    from .. import projects
    return projects.active_meta()


# Expose the active project to every template (topbar chip) without threading it
# through each route's context.
templates.env.globals["active_project"] = _active_project

# Static-asset cache-buster (`?v=` on css/js URLs): a new value per server start,
# so a browser never keeps running last release's JS against this release's app.
templates.env.globals["asset_v"] = str(int(time.time()))

# Canonical severity buckets, worst first — everything non-standard (Log/None/…)
# collapses to "Info" so the dashboard always shows a fixed, ordered set.
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
SEV_CLASS = {"Critical": "crit", "High": "high", "Medium": "med", "Low": "low", "Info": "info"}


def _norm_sev(label: str | None) -> str:
    if not label:
        return "Info"
    canon = label.strip().capitalize()
    return canon if canon in ("Critical", "High", "Medium", "Low") else "Info"


def _disp_sev(f: Finding) -> str:
    """Severity to show on the dashboard — the environmental-adjusted value when
    present, else the scan-native one. (S5.1 will surface base/adj/fw_adj apart.)"""
    return _norm_sev(f.severity_adjusted or f.severity)


def _parse_clauses(raw: str | None) -> list[dict]:
    """Cited clauses as a list of dicts. The canonical store is a JSON list of
    ``{citation, clause_id, section, binding, score, excerpt, reason?}`` (written
    by ``map_findings`` / ``edit_finding``); fall back to a comma-separated list
    of citations for any legacy/plain value."""
    if not raw:
        return []
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return [c if isinstance(c, dict) else {"citation": str(c)} for c in data]
    except (ValueError, TypeError):
        pass
    return [{"citation": c.strip()} for c in raw.split(",") if c.strip()]


def _fw_sev_map(session: Session, version: str) -> dict[int, str]:
    """finding_id -> regulatory-adjusted severity for `version` (fw_adj, else
    environmental, else base). Lets the dashboard reflect the tagging→map escalation."""
    out: dict[int, str] = {}
    for sc in session.exec(select(FindingScore).where(FindingScore.cvss_version == version)).all():
        out[sc.finding_id] = _norm_sev(sc.fw_adj_severity or sc.adj_severity or sc.base_severity)
    return out


# How many findings the dashboard shows before the "Show all" button appears.
_FINDINGS_PREVIEW = 25


def _finding_rows(session: Session) -> list[dict]:
    """Every finding as a dashboard row, worst-severity (framework-adjusted) first.
    Shared by the dashboard and the /findings/all "show all" endpoint."""
    assets = session.exec(select(Asset)).all()
    findings = session.exec(select(Finding)).all()
    fw_sev = _fw_sev_map(session, user_settings.load().get("cvss", "3.1"))
    ip_by_id = {a.id: a.ip_address for a in assets}
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}

    def disp(f: Finding) -> str:
        return fw_sev.get(f.id) or _disp_sev(f)

    return sorted(
        ({
            "id": f.id, "name": f.name, "ip": ip_by_id.get(f.asset_id, "?"),
            "severity": disp(f),
            "cvss": f.cvss_adjusted if f.cvss_adjusted is not None else f.cvss_base,
            "clauses": ", ".join(c.get("citation", "") for c in _parse_clauses(f.regulatory_clauses)),
        } for f in findings),
        key=lambda r: (rank[r["severity"]], -(r["cvss"] or 0.0)),
    )


def _dashboard_context(session: Session) -> dict:
    assets = session.exec(select(Asset)).all()
    findings = session.exec(select(Finding)).all()
    scans = session.exec(select(Scan).order_by(Scan.id.desc())).all()

    primary = user_settings.load().get("cvss", "3.1")
    fw_sev = _fw_sev_map(session, primary)

    def disp(f: Finding) -> str:
        return fw_sev.get(f.id) or _disp_sev(f)

    per_asset: dict[int, int] = {}
    sev_counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev_counts[disp(f)] += 1
        per_asset[f.asset_id] = per_asset.get(f.asset_id, 0) + 1

    asset_rows = sorted(
        ({
            "ip": a.ip_address, "hostname": a.hostname or "—", "os": a.os or "—",
            "criticality": a.criticality.value, "sensitivity": a.data_sensitivity.value,
            "exposure": a.exposure.value, "environment": a.environment.value,
            "n_findings": per_asset.get(a.id, 0),
        } for a in assets),
        key=lambda r: r["n_findings"], reverse=True,
    )

    finding_rows = _finding_rows(session)

    latest = scans[0] if scans else None
    analyzed = session.exec(select(FindingScore)).first() is not None
    return {
        "active_nav": "dashboard",
        "has_findings": len(findings) > 0,
        "analyzed": analyzed,
        "n_assets": len(assets),
        "n_findings": len(findings),
        "n_scans": len(scans),
        "sev_order": SEVERITY_ORDER,
        "sev_class": SEV_CLASS,
        "sev_counts": sev_counts,
        "assets": asset_rows,
        "findings": finding_rows[:_FINDINGS_PREVIEW],
        "findings_more": max(0, len(finding_rows) - _FINDINGS_PREVIEW),
        "n_findings_total": len(finding_rows),
        "db_name": DB_PATH.name,
        "latest_scan": None if latest is None else {
            "tool": latest.tool,
            "target": latest.target,
            "status": latest.status,
            "started": latest.started_at.strftime("%Y-%m-%d %H:%M") if latest.started_at else "",
        },
    }


# --------------------------------------------------------------------------- #
# Finding detail — the three score layers (base / environmental / framework)
# --------------------------------------------------------------------------- #

def _layers(score: FindingScore) -> dict:
    """The three retained layers of one (finding, CVSS version) score row."""
    return {
        "version": score.cvss_version,
        "base": {"score": score.base_score, "severity": _norm_sev(score.base_severity),
                 "vector": score.base_vector, "source": score.source},
        "adj": {"score": score.adj_score, "severity": _norm_sev(score.adj_severity),
                "vector": score.adj_vector},
        "fw": None if score.fw_adj_severity is None else {
            "score": score.fw_adj_score, "severity": _norm_sev(score.fw_adj_severity)},
    }


def _finding_context(session: Session, finding_id: int, msg: str | None = None) -> dict:
    from ..editing import VALID_SEVERITIES

    f = session.get(Finding, finding_id)
    if f is None:
        raise HTTPException(status_code=404, detail="finding not found")
    asset = session.get(Asset, f.asset_id)
    scores = session.exec(
        select(FindingScore).where(FindingScore.finding_id == finding_id)
    ).all()
    # Order the score cards 3.1 then 4.0 (the two versions FinVAP always computes).
    layers = sorted((_layers(s) for s in scores), key=lambda x: x["version"])

    # Headline severity = the regulatory-adjusted (fw_adj) value for the operator's
    # configured CVSS version, falling back through environmental -> base -> native.
    primary = user_settings.load().get("cvss", "3.1")
    head = next((s for s in scores if s.cvss_version == primary), scores[0] if scores else None)
    if head is not None:
        headline = _norm_sev(head.fw_adj_severity or head.adj_severity or head.base_severity)
    else:
        headline = _disp_sev(f)

    ri = session.exec(
        select(FindingReportInput).where(FindingReportInput.finding_id == finding_id)
    ).first()
    report_input = {
        "steps": (ri.steps if ri else "") or "",
        "client_comments": (ri.client_comments if ri else "") or "",
        "postverif_comments": (ri.postverif_comments if ri else "") or "",
        "poc_name": Path(ri.poc_screenshot).name if ri and ri.poc_screenshot else "",
        "postverif_name": Path(ri.postverif_screenshot).name if ri and ri.postverif_screenshot else "",
    }
    return {
        "active_nav": "dashboard",
        "f": f,
        "asset": asset,
        "headline": headline,
        "primary_version": primary,
        "layers": layers,
        "clauses": _parse_clauses(f.regulatory_clauses),
        "override_severities": list(VALID_SEVERITIES),
        "ri": report_input,
        "sev_class": SEV_CLASS,
        "msg": msg,
    }


# --------------------------------------------------------------------------- #
# Audit-history browser — read-only view over the S1 trail (`finvap logs`)
# --------------------------------------------------------------------------- #

def _log_rows(limit: int = 100) -> list[dict]:
    rows = []
    for e in audit.recent(limit):
        rows.append({
            "id": e["id"], "time": (e["ts"] or "")[11:19], "date": (e["ts"] or "")[:10],
            "run": (e["run_id"] or "")[:8], "command": e["command"] or "—",
            "action": e["action"], "target": e["target"] or "",
            "status": e["status"], "summary": e["summary"] or "",
            "has_ai": bool(e["artifact_path"]),
        })
    return rows


def _log_detail(event_id: int) -> dict:
    e = audit.get(event_id)
    if e is None:
        raise HTTPException(status_code=404, detail="audit event not found")
    detail = None
    if e.get("detail"):
        try:
            detail = json.dumps(json.loads(e["detail"]), indent=2)
        except (ValueError, TypeError):
            detail = e["detail"]
    # If this event was an LLM call, load its artifact to show the masking proof.
    artifact = None
    ap = e.get("artifact_path")
    if ap and Path(ap).exists():
        try:
            artifact = json.loads(Path(ap).read_text())
        except (OSError, ValueError):
            artifact = None
    return {"active_nav": "logs", "e": e, "detail_json": detail, "artifact": artifact}


# --------------------------------------------------------------------------- #
# Asset tagging (S5.2) — the four context tags drive the whole risk score, then
# score → map recompute (mapping needs an LLM; degrades gracefully without one).
# --------------------------------------------------------------------------- #

def _tag_row(a: Asset, n_findings: int, saved: bool = False) -> dict:
    return {"id": a.id, "ip": a.ip_address, "hostname": a.hostname or "—",
            "n_findings": n_findings, "saved": saved,
            "tags": {field: getattr(a, field).value for field, _, _ in TAG_FIELDS}}


# --------------------------------------------------------------------------- #
# Setup / "New assessment" (S5 rework) — the entry page after a scan: run
# options + per-asset tags, then the upfront pass (score → map → AI prose).
# Recomputing (re-score + map after a tag change) also lives here — no separate
# Tagging page.
# --------------------------------------------------------------------------- #

# The run settings shown on the setup page (the LLM/scoring inputs). `offline` is
# intentionally NOT surfaced: scoring always uses the online NVD and falls back to
# scan-native/derived vectors at runtime if the NVD is unreachable.
_SETUP_KEYS = [k for k in user_settings.KEYS
               if k["key"] in ("framework", "cvss", "provider", "model", "template")]


def _templates_available() -> list[str]:
    """The .docx report templates the operator can pick, newest name-sorted."""
    d = config.TEMPLATES_DIR
    return sorted(p.name for p in d.glob("*.docx")) if d.exists() else []


def _setup_save(form) -> str | None:
    """Persist the Setup form: run settings (validated) + each asset's four tags.
    Returns an error message, or None on success."""
    values: dict = {}
    for key in ("framework", "cvss", "provider", "model", "template"):
        if form.get(key) is not None:
            values[key] = (form.get(key) or "").strip()
    # The model dropdown's "custom…" option defers to a free-text field.
    if values.get("model") == "__custom__":
        values["model"] = (form.get("model_custom") or "").strip()
    for key, valid in _CHOICES.items():
        if key in ("framework", "cvss", "provider") and values.get(key) not in (None, "") \
                and values[key] not in valid:
            return f"Invalid {key}: {values[key]}"
    if values.get("template") and values["template"] not in _templates_available():
        return f"Unknown report template: {values['template']}"
    user_settings.save(values)
    # Cloud API keys (openai/anthropic) -> the gitignored secrets file. A blank
    # field leaves the stored key untouched (the Save/Clear buttons on the key
    # rows are the primary path). The key itself never reaches the audit trail.
    for prov in ("openai", "anthropic"):
        if (new_key := (form.get(f"{prov}_api_key") or "").strip()):
            config.set_api_key(prov, new_key)
            audit.record("config.api_key", command="web", target=prov,
                         summary=f"{prov} API key updated")
    with db.get_session() as session:
        for a in session.exec(select(Asset)).all():
            for field in TAG_FIELD_NAMES:
                v = form.get(f"t_{a.id}_{field}")
                if v:
                    try:
                        setattr(a, field, TAG_ENUM[field](v))
                    except ValueError:
                        pass
            session.add(a)
        session.commit()
    return None


def _setup_context(session: Session) -> dict:
    per_asset: dict[int, int] = {}
    for f in session.exec(select(Finding)).all():
        per_asset[f.asset_id] = per_asset.get(f.asset_id, 0) + 1
    rows = sorted((_tag_row(a, per_asset.get(a.id, 0)) for a in session.exec(select(Asset)).all()),
                  key=lambda r: r["n_findings"], reverse=True)
    return {"active_nav": "setup", "config": user_settings.effective(),
            "run_keys": _SETUP_KEYS, "assets": rows, "tag_fields": TAG_FIELD_NAMES,
            "tag_labels": TAG_LABELS, "tag_options": TAG_OPTIONS,
            "tag_help": TAG_OPTION_HELP, "templates_available": _templates_available(),
            "api_keys": {p: config.api_key_source(p) for p in ("openai", "anthropic")}}


def _analysis_work(progress) -> dict:
    """Background job: score → map → AI prose over the whole DB, reporting progress.
    Mapping + prose need an LLM (degrade gracefully). Returns the result context."""
    from ..compliance import map_findings
    from ..reporting import rewrite_findings
    from ..reporting.providers import get_provider
    from ..risk import score_findings

    saved = user_settings.load()
    cvss, framework = saved.get("cvss", "3.1"), saved.get("framework", "rmit")
    result = {"framework": framework.upper(), "score": None, "map": None,
              "prose": None, "map_note": None, "error": None}
    try:
        with audit.run("web.analyze", target=framework):
            progress(2, "scoring findings…")
            _, result["score"] = score_findings(
                display_version=cvss, offline=bool(saved.get("offline", False)),
                progress=lambda d, t, s="": progress(2 + 13 * d / max(t, 1), f"scoring {d}/{t}", s))
            prov = get_provider(saved.get("provider") or None, saved.get("model") or None)
            if prov.name == "template":
                result["map_note"] = ("Mapping + AI prose need an LLM — none configured. "
                                       "Pick a provider above and re-run.")
                progress(100, "scored (no LLM)")
            else:
                ok, detail = prov.available()
                if not ok:
                    result["map_note"] = f"Mapping + prose skipped — LLM not ready: {detail}"
                else:
                    result["map"] = map_findings(
                        framework=framework, provider=prov,
                        progress=lambda d, t, s="": progress(15 + 42 * d / max(t, 1), f"mapping {d}/{t}", s))
                    result["prose"] = rewrite_findings(
                        provider=saved.get("provider") or None, model=saved.get("model") or None,
                        progress=lambda d, t, s="": progress(57 + 42 * d / max(t, 1), f"writing prose {d}/{t}", s))
    except Exception as e:  # noqa: BLE001 — surface, don't crash the UI
        result["error"] = f"{type(e).__name__}: {e}"
    return result


def _recompute_work(progress) -> dict:
    """Background job: score → map (no prose rewrite). Mapping needs an LLM;
    degrades gracefully. Returns the result context."""
    from ..compliance import map_findings
    from ..reporting.providers import get_provider
    from ..risk import score_findings

    saved = user_settings.load()
    cvss, framework = saved.get("cvss", "3.1"), saved.get("framework", "rmit")
    result = {"framework": framework, "cvss": cvss,
              "score": None, "map": None, "map_note": None, "error": None}
    try:
        with audit.run("web.recompute", target=framework):
            progress(3, "scoring findings…")
            _, result["score"] = score_findings(
                display_version=cvss, offline=bool(saved.get("offline", False)),
                progress=lambda d, t, s="": progress(3 + 27 * d / max(t, 1), f"scoring {d}/{t}", s))
            prov = get_provider(saved.get("provider") or None, saved.get("model") or None)
            if prov.name == "template":
                result["map_note"] = ("Mapping needs an LLM — none configured. "
                                       "Pick a provider on Setup, then recompute.")
                progress(100, "scored (no LLM)")
            else:
                ok, detail = prov.available()
                if not ok:
                    result["map_note"] = f"Mapping skipped — LLM not ready: {detail}"
                else:
                    result["map"] = map_findings(
                        framework=framework, provider=prov,
                        progress=lambda d, t, s="": progress(30 + 70 * d / max(t, 1), f"mapping {d}/{t}", s))
    except Exception as e:  # noqa: BLE001 — surface, don't crash the UI
        result["error"] = f"{type(e).__name__}: {e}"
    return result


def _rescore_work(progress) -> dict:
    """Background job for the Risk-model page: re-score every finding with the new
    tag weights, then refresh the regulatory (fw_adj) severity from the clauses
    already chosen — **no LLM**, so it's fast and works offline."""
    from ..compliance.mapping import refresh_fw_adj
    from ..risk import score_findings

    saved = user_settings.load()
    cvss, framework = saved.get("cvss", "3.1"), saved.get("framework", "rmit")
    result = {"framework": framework.upper(), "score": None, "fw": None, "error": None}
    try:
        with audit.run("web.rescore", target=framework):
            progress(3, "re-scoring findings…")
            _, result["score"] = score_findings(
                display_version=cvss, offline=bool(saved.get("offline", False)),
                progress=lambda d, t, s="": progress(3 + 60 * d / max(t, 1), f"scoring {d}/{t}", s))
            progress(66, "refreshing regulatory severity…")
            result["fw"] = refresh_fw_adj(
                framework=framework,
                progress=lambda d, t, s="": progress(66 + 33 * d / max(t, 1), f"regulatory {d}/{t}", s))
    except Exception as e:  # noqa: BLE001 — surface, don't crash the UI
        result["error"] = f"{type(e).__name__}: {e}"
    return result


# --------------------------------------------------------------------------- #
# Risk model (#5) — edit what each asset-context tag does to the CVSS score.
# The four tables live in risk/metrics.DEFAULT_TAG_EFFECTS; overrides persist to
# settings.tag_effects. Editing deviates from the grounded defaults (FIPS 199 /
# SP 800-60), so a save is audited (logs only, never the report).
# --------------------------------------------------------------------------- #
_DS_OPTS = ["public", "internal", "confidential", "pii", "financial"]
_CRIT_OPTS = ["low", "medium", "high", "critical"]
_ENV_OPTS = ["production", "staging", "uat", "development"]
_LEVELS = ["L", "M", "H"]


def _risk_model_context() -> dict:
    from ..risk.metrics import DEFAULT_TAG_EFFECTS
    eff = user_settings.effective_tag_effects()
    return {"active_nav": "risk", "eff": eff, "default": DEFAULT_TAG_EFFECTS,
            "ds_opts": _DS_OPTS, "crit_opts": _CRIT_OPTS, "env_opts": _ENV_OPTS,
            "levels": _LEVELS, "customized": bool(user_settings.load_tag_effects())}


def _parse_risk_form(form) -> tuple[dict, list[str]]:
    """Build the overrides block (only leaves that DIFFER from the grounded default)
    and a human-readable diff list, from the Risk-model form."""
    from ..risk.metrics import DEFAULT_TAG_EFFECTS as D
    lv = set(_LEVELS)
    overrides: dict = {}
    diffs: list[str] = []
    for tag, keys in (("data_sensitivity", ("CR", "IR")), ("criticality", ("AR", "floor"))):
        for opt, dflt in D[tag].items():
            for mk in keys:
                raw = (form.get(f"de_{tag}_{opt}_{mk}") or "").strip().upper()
                if raw in lv and raw != dflt[mk]:
                    overrides.setdefault(tag, {}).setdefault(opt, {})[mk] = raw
                    diffs.append(f"{opt} {mk} {dflt[mk]}→{raw}")
    for opt, dflt in D["environment"].items():
        raw = (form.get(f"de_environment_{opt}") or "").strip().upper()
        if raw in lv and raw != dflt:
            overrides.setdefault("environment", {})[opt] = raw
            diffs.append(f"{opt} ceiling {dflt}→{raw}")
    raw = (form.get("de_exposure_internal_av_steps") or "").strip()
    try:
        steps = max(0, min(3, int(raw)))
    except ValueError:
        steps = D["exposure"]["internal_av_steps"]
    if steps != D["exposure"]["internal_av_steps"]:
        overrides.setdefault("exposure", {})["internal_av_steps"] = steps
        diffs.append(f"internal AV steps {D['exposure']['internal_av_steps']}→{steps}")
    return overrides, diffs


# --------------------------------------------------------------------------- #
# Finding editing (S5.3) — human-in-the-loop overrides via editing.edit_finding.
# Each edit sets the durability flag so a later recompute won't clobber it.
# --------------------------------------------------------------------------- #

def _audit_edit(finding_id: int, result: dict) -> None:
    audit.record("finding.edit", command="web", target=f"finding#{finding_id}",
                 summary=f"edited #{finding_id}: {', '.join(result.get('changed', []))}",
                 detail=result)


def _finding_body(request: Request, finding_id: int, msg: str | None = None):
    """Re-render the finding-detail body (the HTMX swap target after an edit)."""
    with db.get_session() as session:
        ctx = _finding_context(session, finding_id, msg=msg)
    return templates.TemplateResponse(request, "_finding_body.html", ctx)


async def _save_upload(finding_id: int, kind: str, upload, remove: bool, current: str | None) -> str | None:
    """Persist a screenshot upload for a finding (S5.5b) under data/uploads/, or
    clear it on `remove`. Returns the stored path (or None). Overwrites any prior
    file for this (finding, kind), whatever its extension."""
    def _clear() -> None:
        if current and Path(current).exists():
            Path(current).unlink()
    if remove:
        _clear()
        return None
    if upload is not None and getattr(upload, "filename", ""):
        data = await upload.read()
        if data:
            ext = Path(upload.filename).suffix.lower()
            if ext not in _IMG_EXTS:
                ext = ".png"
            config.UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
            for old in config.UPLOADS_DIR.glob(f"finding{finding_id}_{kind}.*"):
                old.unlink()
            dest = config.UPLOADS_DIR / f"finding{finding_id}_{kind}{ext}"
            dest.write_bytes(data)
            return str(dest)
    return current  # nothing uploaded, not removed -> keep existing


def _banner(request: Request, msg: str, ok: bool = True):
    return templates.TemplateResponse(request, "_banner.html", {"msg": msg, "ok": ok})


# --------------------------------------------------------------------------- #
# Report generation (S5.5) — fill the .docx template from the DB -> DOCX + PDF.
# The Report page also carries the engagement identity + two-tier SLA forms (they
# shape the report). Run settings live on the Setup page. Synchronous with an HTMX
# spinner (decision #2); the per-finding LLM rewrites can take a while.
# --------------------------------------------------------------------------- #

def _report_context() -> dict:
    from ..reporting import deadlines
    saved = user_settings.load()
    eng = engagement.load()
    with db.get_session() as session:
        n_findings = len(session.exec(select(Finding)).all())
        n_assets = len(session.exec(select(Asset)).all())
    set_identity = sum(1 for k in engagement.FIELDS if eng.get(k))
    return {
        "active_nav": "report",
        "framework": (saved.get("framework") or "rmit").upper(),
        "template": saved.get("template") or "bundled default (VA Template.docx)",
        "provider": saved.get("provider") or "ollama (default)",
        "n_findings": n_findings,
        "n_assets": n_assets,
        "identity_set": set_identity,
        "identity_total": len(engagement.FIELDS),
        "date_keys": engagement.DATE_KEYS,
        # engagement + SLA forms (moved here from the old Settings tab)
        "engagement": eng,
        "engagement_keys": engagement.KEYS,
        "sla": deadlines.merged_sla(user_settings.load_sla()),
        "severities": deadlines.SEVERITIES,
        "sev_class": SEV_CLASS,
    }


def _report_work(date_assessment: str, date_draft: str, draft_final: str,
                 version: str, cover_date: str):
    """Build a background-job function that fills the template -> DOCX (+ PDF),
    reporting coarse progress (the fill engine emits per-stage messages)."""
    def work(progress) -> dict:
        import time

        from ..reporting import TemplateError, fill_template, resolve_template

        saved = user_settings.load()
        framework = saved.get("framework", "rmit")
        cvss_version = saved.get("cvss", "3.1")
        ctx = {"framework": framework.upper(), "docx": None, "pdf": None,
               "warning": None, "error": None}
        try:
            tmpl = resolve_template(saved.get("template") or None)
        except TemplateError as e:
            ctx["error"] = f"Template problem: {e}"
            return ctx

        meta = dict(engagement.load())
        if date_assessment.strip():
            meta["Date_Assessment"] = date_assessment.strip()
        if date_draft.strip():
            meta["Date_DraftReport"] = date_draft.strip()
        meta["__draft_final"] = (draft_final or "Draft").strip()
        meta["__version"] = (version or "0.1").strip()
        if cover_date.strip():
            meta["__cover_date"] = cover_date.strip()

        base = config.EXPORTS_DIR / f"report-{int(time.time())}"
        base.parent.mkdir(parents=True, exist_ok=True)
        pct = [10]

        def _fill_progress(msg):
            pct[0] = min(90, pct[0] + 12)
            progress(pct[0], msg)

        try:
            progress(5, "filling report…")
            with audit.run("web.report", target=framework):
                paths = fill_template(
                    tmpl, base, framework=framework, cvss_version=cvss_version,
                    metadata=meta, target=None,
                    provider=saved.get("provider") or None, model=saved.get("model") or None,
                    sla_overrides=user_settings.load_sla(), pdf=True, progress=_fill_progress)
            for p in paths:
                if p.suffix == ".docx":
                    ctx["docx"] = p.name
                elif p.suffix == ".pdf":
                    ctx["pdf"] = p.name
        except TemplateError as e:
            docx = base.with_suffix(".docx")     # PDF (LibreOffice) can fail, DOCX still written
            if docx.exists():
                ctx["docx"] = docx.name
                ctx["warning"] = f"PDF step failed ({e}); the DOCX was written."
            else:
                ctx["error"] = str(e)
        except Exception as e:  # noqa: BLE001 — surface, don't crash the UI
            ctx["error"] = f"{type(e).__name__}: {e}"
        return ctx
    return work


def create_app() -> FastAPI:
    app = FastAPI(title="FinVAP", docs_url=None, redoc_url=None, openapi_url=None)
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.middleware("http")
    async def _security_headers(request: Request, call_next):
        """Conservative headers for the local UI. Everything is same-origin
        (vendored htmx, local CSS/JS, uploaded images), so a strict CSP fits."""
        resp = await call_next(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Content-Security-Policy", "default-src 'self'; img-src 'self' data:")
        return resp

    @app.get("/healthz", response_class=PlainTextResponse)
    def healthz() -> str:  # liveness probe for the launcher / tests
        return "ok"

    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request):
        db.init_db()  # harmless if the tables already exist
        with db.get_session() as session:
            ctx = _dashboard_context(session)
        # Starlette's current signature: (request, name, context); it injects
        # `request` into the context itself.
        return templates.TemplateResponse(request, "dashboard.html", ctx)

    @app.get("/finding/{finding_id}", response_class=HTMLResponse)
    def finding_detail(request: Request, finding_id: int):
        db.init_db()
        with db.get_session() as session:
            ctx = _finding_context(session, finding_id)
        return templates.TemplateResponse(request, "finding_detail.html", ctx)

    @app.post("/finding/{finding_id}/edit-text", response_class=HTMLResponse)
    def edit_text(request: Request, finding_id: int, name: str = Form(""),
                  description: str = Form(""), solution: str = Form("")):
        from ..editing import EditError, edit_finding
        kwargs: dict = {"description": description, "solution": solution}
        if name.strip():
            kwargs["name"] = name.strip()      # never blank the title
        try:
            result = edit_finding(finding_id, **kwargs)
        except EditError as e:
            return _finding_body(request, finding_id, msg=str(e))
        _audit_edit(finding_id, result)
        return _finding_body(request, finding_id, msg="Text saved.")

    @app.post("/finding/{finding_id}/override", response_class=HTMLResponse)
    def override(request: Request, finding_id: int,
                 severity: str = Form(""), score: str = Form("")):
        from ..editing import EditError, edit_finding
        sev = severity.strip() or None
        sc: float | None = None
        if score.strip():
            try:
                sc = float(score)
            except ValueError:
                return _finding_body(request, finding_id, msg="Score must be a number 0–10.")
        if sev is None and sc is None:
            return _finding_body(request, finding_id, msg="Pick a severity or enter a score.")
        try:
            result = edit_finding(finding_id, severity=sev, score=sc)
        except EditError as e:
            return _finding_body(request, finding_id, msg=str(e))
        _audit_edit(finding_id, result)
        return _finding_body(request, finding_id, msg="Override applied.")

    @app.post("/finding/{finding_id}/clause", response_class=HTMLResponse)
    def clause(request: Request, finding_id: int,
               add_clause: str = Form(""), remove_clause: str = Form("")):
        from ..editing import EditError, edit_finding
        add, rem = add_clause.strip() or None, remove_clause.strip() or None
        if not add and not rem:
            return _finding_body(request, finding_id, msg="Enter a clause to add.")
        try:
            result = edit_finding(finding_id, add_clause=add, remove_clause=rem)
        except EditError as e:
            return _finding_body(request, finding_id, msg=str(e))
        _audit_edit(finding_id, result)
        return _finding_body(request, finding_id, msg="Clauses updated.")

    @app.post("/finding/{finding_id}/clear-override", response_class=HTMLResponse)
    def clear_override(request: Request, finding_id: int):
        from ..editing import EditError, edit_finding
        try:
            result = edit_finding(finding_id, clear_override=True)
        except EditError as e:
            return _finding_body(request, finding_id, msg=str(e))
        _audit_edit(finding_id, result)
        return _finding_body(request, finding_id,
                             msg="Overrides cleared — recompute to restore computed values.")

    @app.post("/finding/{finding_id}/report-input", response_class=HTMLResponse)
    async def save_report_input(request: Request, finding_id: int,
                                steps: str = Form(""), client_comments: str = Form(""),
                                postverif_comments: str = Form(""),
                                poc_screenshot: UploadFile = File(None),
                                postverif_screenshot: UploadFile = File(None),
                                remove_poc: str = Form(""), remove_postverif: str = Form("")):
        db.init_db()
        with db.get_session() as session:
            f = session.get(Finding, finding_id)
            if f is None:
                raise HTTPException(status_code=404, detail="finding not found")
            ri = session.exec(select(FindingReportInput).where(
                FindingReportInput.finding_id == finding_id)).first()
            if ri is None:
                ri = FindingReportInput(finding_id=finding_id)
            ri.steps = steps
            ri.client_comments = client_comments
            ri.postverif_comments = postverif_comments
            ri.poc_screenshot = await _save_upload(
                finding_id, "poc", poc_screenshot, bool(remove_poc), ri.poc_screenshot)
            ri.postverif_screenshot = await _save_upload(
                finding_id, "postverif", postverif_screenshot, bool(remove_postverif),
                ri.postverif_screenshot)
            session.add(ri); session.commit()
            audit.record("finding.report_input", command="web", target=f"finding#{finding_id}",
                         summary=f"report inputs saved for finding #{finding_id}")
        return _finding_body(request, finding_id, msg="Report inputs saved.")

    @app.post("/finding/{finding_id}/delete", response_class=HTMLResponse)
    async def delete_finding_route(request: Request, finding_id: int):
        from .. import maintenance
        try:
            info = maintenance.delete_finding(finding_id)
        except LookupError:
            raise HTTPException(status_code=404, detail="finding not found")
        audit.record("delete.finding", command="web", target=f"finding#{finding_id}",
                     summary=f"deleted finding #{finding_id} "
                             f"({(info.get('name') or '')[:50]}, {info['scores']} score(s))")
        form = await request.form()
        # From the finding page: bounce back to the dashboard (the finding is gone).
        if form.get("redirect"):
            return HTMLResponse("", headers={"HX-Redirect": "/"})
        # From a dashboard row: re-render the findings table in place.
        with db.get_session() as session:
            rows = _finding_rows(session)
        return templates.TemplateResponse(request, "_findings_table.html",
                                          {"findings": rows, "findings_more": False,
                                           "n_findings_total": len(rows), "sev_class": SEV_CLASS})

    @app.get("/uploads/{name}")
    def serve_upload(name: str):
        from fastapi.responses import FileResponse
        safe = Path(name).name
        p = config.UPLOADS_DIR / safe
        if safe != name or p.suffix.lower() not in _IMG_EXTS or not p.is_file():
            raise HTTPException(status_code=404, detail="not found")
        return FileResponse(str(p))

    @app.get("/logs", response_class=HTMLResponse)
    def logs(request: Request):
        return templates.TemplateResponse(
            request, "logs.html", {"active_nav": "logs", "events": _log_rows()})

    @app.get("/logs/{event_id}", response_class=HTMLResponse)
    def log_detail(request: Request, event_id: int):
        return templates.TemplateResponse(
            request, "log_detail.html", _log_detail(event_id))

    @app.get("/progress/{job_id}", response_class=HTMLResponse)
    def progress(request: Request, job_id: str):
        from . import jobs
        j = jobs.get(job_id)
        if j is None:
            raise HTTPException(status_code=404, detail="unknown job")
        if j["done"]:
            jobs.discard(job_id)
            ctx = j["result"] if j["result"] is not None else {"error": j["error"]}
            # HTTP 286 tells htmx to stop polling and swap in the final result
            return templates.TemplateResponse(request, j["result_template"], ctx, status_code=286)
        return templates.TemplateResponse(request, "_progress.html",
                                          {"percent": j["percent"], "label": j["label"],
                                           "detail": j.get("detail", "")})

    @app.get("/setup", response_class=HTMLResponse)
    def setup_page(request: Request):
        db.init_db()
        with db.get_session() as session:
            ctx = _setup_context(session)
        # Discover the models server-side so the select arrives already filled —
        # an on-load fetch can strand the field on "discovering models…" if the
        # box is busy. GET /models stays for provider changes + the retry link.
        from ..reporting.providers import model_choices
        ids, status, live = model_choices(ctx["config"].get("provider") or "ollama")
        ctx.update(model_ids=ids, model_status=status, model_unavailable=not live,
                   model_current=user_settings.load().get("model", "") or "")
        return templates.TemplateResponse(request, "setup.html", ctx)

    def _setup_job(request: Request, form, work, result_template: str):
        """Save the Setup form, then kick off `work` as a background job."""
        db.init_db()
        from . import jobs
        if jobs.is_running():
            return _banner(request, "An analysis or report is already running — "
                                    "wait for it to finish before starting another.", ok=False)
        err = _setup_save(form)
        if err:
            return _banner(request, err, ok=False)
        try:
            jid = jobs.start(work, result_template)
        except jobs.JobBusy:
            return _banner(request, "An analysis or report is already running — "
                                    "wait for it to finish before starting another.", ok=False)
        return templates.TemplateResponse(request, "_job.html",
                                          {"job_id": jid, "percent": 0, "label": "starting…"})

    def _api_keys_fragment(request: Request, msg: str | None = None, ok: bool = True):
        """Re-render the API-key rows and tell the page to re-discover models
        (the provider select listens for `refresh-models`)."""
        resp = templates.TemplateResponse(
            request, "_api_keys.html",
            {"api_keys": {p: config.api_key_source(p) for p in ("openai", "anthropic")},
             "key_msg": msg, "key_msg_ok": ok})
        resp.headers["HX-Trigger"] = "refresh-models"
        return resp

    @app.post("/setup/api-key/{prov}", response_class=HTMLResponse)
    async def save_api_key(request: Request, prov: str):
        if prov not in ("openai", "anthropic"):
            raise HTTPException(404)
        form = await request.form()
        key = (form.get(f"{prov}_api_key") or "").strip()
        if not key:
            return _api_keys_fragment(request, f"Paste a {prov} key first.", ok=False)
        config.set_api_key(prov, key)
        audit.record("config.api_key", command="web", target=prov,
                     summary=f"{prov} API key updated")
        msg = f"{prov} key saved — models refreshed."
        if (form.get("provider") or "") != prov:
            msg += f" Set the LLM provider above to {prov} to see its models."
        return _api_keys_fragment(request, msg)

    @app.post("/setup/api-key/{prov}/clear", response_class=HTMLResponse)
    async def clear_api_key(request: Request, prov: str):
        if prov not in ("openai", "anthropic"):
            raise HTTPException(404)
        config.set_api_key(prov, "")
        audit.record("config.api_key", command="web", target=prov,
                     summary=f"{prov} API key cleared")
        return _api_keys_fragment(request, f"{prov} key cleared.")

    @app.post("/setup/start", response_class=HTMLResponse)
    async def setup_start(request: Request):
        # Save run settings + tags, then the full pass (score -> map -> AI prose).
        return _setup_job(request, await request.form(), _analysis_work, "_setup_result.html")

    @app.post("/setup/recompute", response_class=HTMLResponse)
    async def setup_recompute(request: Request):
        # Save run settings + tags, then re-score + re-map only (no prose rewrite).
        return _setup_job(request, await request.form(), _recompute_work, "_recompute_result.html")

    # --- Risk model: edit what each context tag does to the score (#5) ---
    @app.get("/risk-model", response_class=HTMLResponse)
    def risk_model(request: Request):
        return templates.TemplateResponse(request, "risk_model.html", _risk_model_context())

    @app.get("/cvss", response_class=HTMLResponse)
    def cvss_calculator(request: Request):
        """Standalone CVSS 3.1 / 4.0 calculator (client-side scoring)."""
        return templates.TemplateResponse(request, "cvss.html", {"active_nav": "cvss"})

    def _risk_form(request: Request, msg: str | None = None, ok: bool = True):
        ctx = _risk_model_context()
        ctx["msg"] = msg
        ctx["msg_ok"] = ok
        return templates.TemplateResponse(request, "_risk_model_form.html", ctx)

    @app.post("/risk-model", response_class=HTMLResponse)
    async def save_risk_model(request: Request):
        overrides, diffs = _parse_risk_form(await request.form())
        user_settings.save_tag_effects(overrides)
        if diffs:
            shown = "; ".join(diffs[:12]) + (" …" if len(diffs) > 12 else "")
            audit.record("tag_effects.change", command="web", target="risk-model",
                         summary=f"tag effects changed ({len(diffs)}): {shown}",
                         detail={"overrides": overrides})
            msg = (f"Saved — {len(diffs)} value(s) differ from the grounded defaults "
                   "(FIPS 199 / SP 800-60). Recompute to apply them to the findings.")
        else:
            audit.record("tag_effects.change", command="web", target="risk-model",
                         summary="tag effects saved (all at grounded defaults)")
            msg = "Saved — all values at the grounded defaults (FIPS 199 / SP 800-60)."
        return _risk_form(request, msg=msg)

    @app.post("/risk-model/reset", response_class=HTMLResponse)
    async def reset_risk_model(request: Request):
        removed = user_settings.reset_tag_effects()
        audit.record("tag_effects.change", command="web", target="risk-model",
                     summary="tag effects reset to grounded defaults" if removed
                             else "tag effects already at defaults")
        return _risk_form(request, msg="Reset to the grounded defaults (FIPS 199 / SP 800-60)."
                          if removed else "Already at the grounded defaults.")

    @app.post("/risk-model/recompute", response_class=HTMLResponse)
    async def recompute_risk_model(request: Request):
        # Persist the current form first, then re-score (LLM-free) so the change lands.
        from . import jobs
        overrides, diffs = _parse_risk_form(await request.form())
        user_settings.save_tag_effects(overrides)
        if diffs:
            audit.record("tag_effects.change", command="web", target="risk-model",
                         summary=f"tag effects changed ({len(diffs)}): "
                                 + "; ".join(diffs[:12]) + (" …" if len(diffs) > 12 else ""),
                         detail={"overrides": overrides})
        try:
            jid = jobs.start(_rescore_work, "_rescore_result.html")
        except jobs.JobBusy:
            return _banner(request, "An analysis or report is already running — "
                                    "wait for it to finish before recomputing.", ok=False)
        return templates.TemplateResponse(request, "_job.html",
                                          {"job_id": jid, "percent": 0, "label": "starting…"})

    # Engagement identity + remediation SLA live on the Report page (they shape the
    # report). Run settings live on the Setup page. There is no standalone Settings tab.
    @app.post("/report/engagement", response_class=HTMLResponse)
    async def save_engagement(request: Request):
        form = await request.form()
        engagement.save({k: (form.get(k) or "").strip() for k in engagement.FIELDS})
        return _banner(request, "Engagement details saved.")

    @app.post("/report/sla", response_class=HTMLResponse)
    async def save_sla(request: Request):
        from ..reporting import deadlines
        form = await request.form()
        sla: dict = {}
        for sev in deadlines.SEVERITIES:
            tiers = {}
            for tier in ("ext", "int"):
                raw = form.get(f"sla_{sev}_{tier}")
                if raw:
                    try:
                        v = int(raw)
                        if v < 1:
                            raise ValueError
                    except ValueError:
                        return _banner(request, f"SLA {sev}/{tier} must be a positive integer.", ok=False)
                    tiers[tier] = v
            if tiers:
                sla[sev] = tiers
        user_settings.save_sla(sla)
        return _banner(request, "Remediation SLA saved.")

    @app.get("/models", response_class=HTMLResponse)
    def discover(request: Request, provider: str = "ollama"):
        from ..reporting.providers import model_choices
        ids, status, live = model_choices(provider)
        current = user_settings.load().get("model", "") or ""
        return templates.TemplateResponse(request, "_model_select.html",
                                          {"ids": ids, "status": status,
                                           "unavailable": not live, "current": current})

    @app.get("/findings/all", response_class=HTMLResponse)
    def findings_all(request: Request):
        """The full findings table — swapped in when the operator clicks Show all."""
        with db.get_session() as session:
            rows = _finding_rows(session)
        return templates.TemplateResponse(request, "_findings_table.html",
                                          {"findings": rows, "findings_more": False,
                                           "n_findings_total": len(rows), "sev_class": SEV_CLASS})

    @app.get("/projects", response_class=HTMLResponse)
    def projects_page(request: Request):
        from .. import projects
        return templates.TemplateResponse(request, "projects.html",
                                          {"active_nav": "projects",
                                           "projects": projects.list_projects()})

    @app.post("/projects/{slug}/activate")
    def project_activate(slug: str):
        from fastapi.responses import RedirectResponse

        from .. import projects
        if projects.exists(slug):
            projects.activate(slug)
        return RedirectResponse("/", status_code=303)

    @app.post("/projects/{slug}/rename")
    async def project_rename(request: Request, slug: str):
        from urllib.parse import urlparse

        from fastapi.responses import RedirectResponse

        from .. import projects
        form = await request.form()
        projects.rename(slug, (form.get("name") or "").strip())
        # Land back where the rename came from (the topbar menu works on any
        # page); only ever a local path, defaulting to the projects list.
        back = urlparse(request.headers.get("referer") or "").path or "/projects"
        return RedirectResponse(back if back.startswith("/") else "/projects",
                                status_code=303)

    @app.post("/projects/{slug}/delete")
    def project_delete(slug: str):
        from fastapi.responses import RedirectResponse

        from .. import projects
        was_active = projects.active() == slug
        projects.delete(slug)
        if was_active:                       # keep a live DB bound
            rest = projects.list_projects()
            if rest:
                projects.activate(rest[0]["slug"])
            else:
                db.bind(config.DB_PATH)
        return RedirectResponse("/projects", status_code=303)

    @app.get("/report", response_class=HTMLResponse)
    def report_page(request: Request):
        db.init_db()
        return templates.TemplateResponse(request, "report.html", _report_context())

    @app.post("/report/generate", response_class=HTMLResponse)
    def generate_report(request: Request, date_assessment: str = Form(""),
                        date_draft: str = Form(""), draft_final: str = Form("Draft"),
                        version: str = Form("0.1"), cover_date: str = Form("")):
        db.init_db()
        from . import jobs
        work = _report_work(date_assessment, date_draft, draft_final, version, cover_date)
        try:
            jid = jobs.start(work, "_report_result.html")
        except jobs.JobBusy:
            return _banner(request, "An analysis or report is already running — "
                                    "wait for it to finish before starting another.", ok=False)
        return templates.TemplateResponse(request, "_job.html",
                                          {"job_id": jid, "percent": 0, "label": "starting…"})

    @app.get("/report/download/{name}")
    def download_report(name: str):
        from fastapi.responses import FileResponse
        safe = Path(name).name                      # strip any path — no traversal
        p = config.EXPORTS_DIR / safe
        if safe != name or p.suffix not in (".docx", ".pdf") or not p.is_file():
            raise HTTPException(status_code=404, detail="report not found")
        return FileResponse(str(p), filename=safe)

    return app
