"""The unified data model — the spine every module plugs into.

Nmap populates Assets + Ports (discovery); GVM populates Findings
(vulnerabilities). The risk engine (Obj 3) reads an Asset's context tags to fill
the `*_adjusted` fields on a Finding; the compliance engine (Obj 1) fills
`regulatory_clauses`.
"""
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from sqlmodel import Field, Relationship, SQLModel


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Criticality(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class DataSensitivity(str, Enum):
    public = "public"
    internal = "internal"
    confidential = "confidential"
    pii = "pii"
    financial = "financial"


class Exposure(str, Enum):
    internal = "internal"
    external = "external"


class Environment(str, Enum):
    """Deployment tier — caps the environmental Security Requirements so that a
    non-production box can't be over-scored just because it carries a high
    data/criticality tag (Phase 2). production = full weight; lower tiers cap down.
    """
    production = "production"
    staging = "staging"
    uat = "uat"
    development = "development"


class Asset(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    ip_address: str = Field(index=True, unique=True)
    hostname: Optional[str] = None
    os: Optional[str] = None

    # Context tags consumed by the risk engine (Objective 3).
    criticality: Criticality = Field(default=Criticality.medium)
    data_sensitivity: DataSensitivity = Field(default=DataSensitivity.internal)
    exposure: Exposure = Field(default=Exposure.internal)
    environment: Environment = Field(default=Environment.production)
    notes: Optional[str] = None
    created_at: datetime = Field(default_factory=_utcnow)

    ports: list["Port"] = Relationship(back_populates="asset")
    findings: list["Finding"] = Relationship(back_populates="asset")


class Port(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    asset_id: int = Field(foreign_key="asset.id", index=True)
    port: int
    protocol: str = "tcp"
    state: Optional[str] = None
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None

    asset: Optional[Asset] = Relationship(back_populates="ports")


class Scan(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    target: str
    tool: str
    status: str = "completed"
    started_at: datetime = Field(default_factory=_utcnow)
    finished_at: Optional[datetime] = None
    raw_output_path: Optional[str] = None


class Finding(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    scan_id: Optional[int] = Field(default=None, foreign_key="scan.id", index=True)
    asset_id: int = Field(foreign_key="asset.id", index=True)
    tool: str
    name: str
    description: Optional[str] = None
    # Richer NVT context (GVM tags) — used to build the regulatory-mapping query
    # (Obj 1) and later the AI report (Obj 4).
    summary: Optional[str] = None
    impact: Optional[str] = None
    affected: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    cve: Optional[str] = None
    cvss_base: Optional[float] = None
    cvss_version: Optional[str] = None  # native version the scanner reported: "2.0" | "3.1"
    cvss_vector: Optional[str] = None   # native base vector from the scan (Obj 3 input)
    severity: Optional[str] = None
    qod: Optional[int] = None  # GVM Quality of Detection (%)
    solution: Optional[str] = None
    references: Optional[str] = None

    # Filled by the risk engine (Obj 3). cvss_adjusted/severity_adjusted mirror the
    # *currently displayed* CVSS version's environmental score; the full per-version
    # breakdown lives in FindingScore. regulatory_clauses is filled by Obj 1.
    cvss_adjusted: Optional[float] = None
    severity_adjusted: Optional[str] = None
    regulatory_clauses: Optional[str] = None

    # Human-in-the-loop overrides (Phase 5, NFR). When set, `finvap score` / `map`
    # leave this finding's adjusted score / cited clauses untouched so a manual
    # edit survives a re-run. Cleared with `finvap edit finding <id> --clear-override`.
    score_overridden: bool = Field(default=False)
    clauses_overridden: bool = Field(default=False)
    # Set when the description/solution has been finalised (a manual edit, or the
    # AI prose step). The `rewrite_findings` pipeline step leaves it untouched so a
    # human edit isn't regenerated. Cleared with `--clear-override`.
    text_overridden: bool = Field(default=False)
    created_at: datetime = Field(default_factory=_utcnow)

    asset: Optional[Asset] = Relationship(back_populates="findings")
    scores: list["FindingScore"] = Relationship(back_populates="finding")


class FindingScore(SQLModel, table=True):
    """One row per (finding, CVSS version) — Obj 3 scoring output.

    Three score layers are retained per version, nothing overwritten:
      1. base/true   — the standards score, with a ``source`` provenance label
                       (scan = native vector, nvd = NVD official, derived = our
                       heuristic cross-version conversion).
      2. adjusted    — CVSS *environmental* recompute from the asset's context
                       tags (this phase).
      3. fw_adjusted — framework-reclassified score (Phase 3 slot; nullable now).

    Both 3.1 and 4.0 are always computed and stored so the CLI can switch the
    displayed version instantly without re-scoring.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    finding_id: int = Field(foreign_key="finding.id", index=True)
    cvss_version: str  # "3.1" | "4.0"

    base_vector: str
    base_score: float
    base_severity: str
    source: str  # "scan" | "nvd" | "derived"

    adj_vector: str
    adj_score: float
    adj_severity: str

    # Phase 3 (regulatory framework) slot — left null until Obj 1 fills it.
    fw_adj_score: Optional[float] = None
    fw_adj_severity: Optional[str] = None

    created_at: datetime = Field(default_factory=_utcnow)

    finding: Optional[Finding] = Relationship(back_populates="scores")


class FindingReportInput(SQLModel, table=True):
    """Manual, human-entered report content for a finding (S5.5b, the deferred
    #6 fields): PoC + post-verification screenshots, reproduction steps and
    client / post-verification comments. Kept out of ``Finding`` so ingest /
    score / map never touch it; filled into the §4 finding block at report time.
    One row per finding (screenshots are paths under ``data/uploads/``).
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    finding_id: int = Field(foreign_key="finding.id", index=True, unique=True)
    poc_screenshot: Optional[str] = None            # path under data/uploads/
    steps: Optional[str] = None                     # reproduction steps (one per line)
    client_comments: Optional[str] = None
    postverif_screenshot: Optional[str] = None      # path under data/uploads/
    postverif_comments: Optional[str] = None
    created_at: datetime = Field(default_factory=_utcnow)
