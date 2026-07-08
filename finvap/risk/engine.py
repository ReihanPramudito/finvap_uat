"""The risk-scoring engine (Obj 3).

For each finding it produces, per CVSS version, three layers:
  base      -- official score where possible (scan-native vector, then NVD),
               else a derived cross-version conversion (labelled accordingly);
  adjusted  -- CVSS *environmental* recompute from the asset's context tags;
  fw_adj    -- left for Phase 3 (regulatory reclassification).

Both 3.1 and 4.0 are always computed so the CLI can switch display instantly.
The engine is deterministic and idempotent: re-running ``score_findings`` upserts
one FindingScore row per (finding, version).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import convert, metrics
from .nvd import NvdClient

SUPPORTED_VERSIONS = ("3.1", "4.0")


@dataclass
class Layer:
    version: str
    base_vector: str
    base_score: float
    base_severity: str
    source: str  # "scan" | "nvd" | "derived"
    adj_vector: str
    adj_score: float
    adj_severity: str
    reasons: list[str] = field(default_factory=list)


@dataclass
class Scored:
    finding_id: int | None
    name: str
    asset_ip: str
    cve: str | None
    layers: dict[str, Layer]


def _cvss_scores(version: str, base_vector: str, adj_vector: str) -> tuple[float, float]:
    """Return (base_score, environmental_score) for the given version's vectors."""
    if version == "3.1":
        from cvss import CVSS3
        base = CVSS3(base_vector).scores()[0]
        env = CVSS3(adj_vector).scores()[2]  # (base, temporal, environmental)
        return float(base), float(env)
    if version == "4.0":
        from cvss import CVSS4
        # In v4.0 the environmental metrics are part of the single score, so the
        # adjusted vector's score *is* the environmental score.
        return float(CVSS4(base_vector).base_score), float(CVSS4(adj_vector).base_score)
    raise ValueError(f"unsupported CVSS version {version!r}")


def _resolve_base(native_vector: str, native_version: str | None, cve: str | None,
                  target: str, nvd: NvdClient) -> tuple[str, str]:
    """Resolve a base vector for the target version. Returns (vector, source).

    Provenance order (most authoritative first): the scan's native vector ->
    NVD's official vector -> our derived conversion.
    """
    nv = (native_version or convert.detect_version(native_vector))
    # Native vector already in the target family (treat 3.0/3.1 as one for 3.1).
    if target == "3.1" and nv.startswith("3"):
        return native_vector, "scan"
    if target == "4.0" and nv == "4.0":
        return native_vector, "scan"

    if cve:
        official = nvd.vector_for(cve, target)
        if official:
            return official, "nvd"

    return convert.to_version(native_vector, target)[0], "derived"


def score_one(native_vector: str, native_version: str | None, cve: str | None,
              asset, nvd: NvdClient, versions=SUPPORTED_VERSIONS) -> dict[str, Layer]:
    """Pure scoring for a single finding (no DB). Returns {version: Layer}."""
    layers: dict[str, Layer] = {}
    for version in versions:
        base_vector, source = _resolve_base(native_vector, native_version, cve, version, nvd)
        base_av = convert.parse_vector(base_vector)[1].get("AV", "N")
        env_metrics, reasons = metrics.environmental_metrics(asset, base_av)
        adj_vector = metrics.append_metrics(base_vector, env_metrics)
        base_score, adj_score = _cvss_scores(version, base_vector, adj_vector)
        layers[version] = Layer(
            version=version,
            base_vector=base_vector,
            base_score=base_score,
            base_severity=metrics.band(base_score),
            source=source,
            adj_vector=adj_vector,
            adj_score=adj_score,
            adj_severity=metrics.band(adj_score),
            reasons=reasons,
        )
    return layers


def score_findings(*, display_version: str = "3.1", offline: bool = False,
                   api_key: str | None = None, versions=SUPPORTED_VERSIONS,
                   progress=None) -> tuple[list[Scored], dict]:
    """Score every finding that has a native vector; persist FindingScore rows.

    ``display_version``'s environmental score is mirrored onto
    Finding.cvss_adjusted / severity_adjusted for the at-a-glance tables. Returns
    (scored, stats). ``progress`` is an optional callback(done, total, detail)
    where ``detail`` names the finding currently being worked on.
    """
    from sqlmodel import select

    from ..db import get_session
    from ..models import Asset, Finding, FindingScore

    nvd = NvdClient(offline=offline, api_key=api_key)
    scored: list[Scored] = []
    stats = {"scored": 0, "skipped": 0, "overridden": 0, "sources": {}}

    with get_session() as session:
        assets = {a.id: a for a in session.exec(select(Asset)).all()}
        findings = session.exec(select(Finding)).all()
        total = len(findings)

        for idx, f in enumerate(findings, 1):
            if progress:
                progress(idx, total, f.name or f.cve or "")
            # Preserve a manual override (Phase 5): leave its adjusted score alone.
            if f.score_overridden:
                stats["overridden"] += 1
                continue
            if not f.cvss_vector:
                stats["skipped"] += 1
                continue
            asset = assets.get(f.asset_id)
            if asset is None:
                stats["skipped"] += 1
                continue

            layers = score_one(f.cvss_vector, f.cvss_version, f.cve, asset, nvd, versions)

            # Upsert one row per (finding, version) — idempotent re-scoring.
            existing = {
                fs.cvss_version: fs
                for fs in session.exec(
                    select(FindingScore).where(FindingScore.finding_id == f.id)
                ).all()
            }
            for version, layer in layers.items():
                fs = existing.get(version) or FindingScore(
                    finding_id=f.id, cvss_version=version
                )
                fs.base_vector = layer.base_vector
                fs.base_score = layer.base_score
                fs.base_severity = layer.base_severity
                fs.source = layer.source
                fs.adj_vector = layer.adj_vector
                fs.adj_score = layer.adj_score
                fs.adj_severity = layer.adj_severity
                session.add(fs)
                stats["sources"][layer.source] = stats["sources"].get(layer.source, 0) + 1

            disp = layers.get(display_version)
            if disp:
                f.cvss_adjusted = disp.adj_score
                f.severity_adjusted = disp.adj_severity
                session.add(f)

            scored.append(Scored(
                finding_id=f.id, name=f.name,
                asset_ip=asset.ip_address, cve=f.cve, layers=layers,
            ))
            stats["scored"] += 1

        session.commit()

    return scored, stats
