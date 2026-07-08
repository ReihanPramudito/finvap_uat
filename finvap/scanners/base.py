"""Common contract for all scanners.

Every scanner returns a ``ScanResult`` made of plain dataclasses. This keeps the
scanners decoupled from the database — ``finvap.ingest`` is the only place that
knows how to persist a result. Adding a new tool (e.g. Nuclei) is just a matter
of producing the same dataclasses.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional, Protocol


@dataclass
class DiscoveredAsset:
    ip_address: str
    hostname: Optional[str] = None
    os: Optional[str] = None


@dataclass
class DiscoveredPort:
    ip_address: str
    port: int
    protocol: str = "tcp"
    state: Optional[str] = None
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None


@dataclass
class DiscoveredFinding:
    ip_address: str
    name: str
    tool: str
    description: Optional[str] = None
    summary: Optional[str] = None
    impact: Optional[str] = None
    affected: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    cve: Optional[str] = None
    cvss_base: Optional[float] = None
    cvss_version: Optional[str] = None
    cvss_vector: Optional[str] = None
    severity: Optional[str] = None
    qod: Optional[int] = None
    solution: Optional[str] = None
    references: Optional[str] = None


@dataclass
class ScanResult:
    tool: str
    target: str
    assets: list[DiscoveredAsset] = field(default_factory=list)
    ports: list[DiscoveredPort] = field(default_factory=list)
    findings: list[DiscoveredFinding] = field(default_factory=list)
    raw_output: Optional[str] = None
    raw_output_path: Optional[str] = None
    # Scanner-reported terminal status (e.g. GVM "Done"/"Stopped"/"Interrupted").
    # Lets the CLI warn when results may be partial.
    status: Optional[str] = None
    # What the scanner actually executed, for the audit trail. ``command`` is the
    # literal argv (nmap); ``meta`` carries tool-specific detail (GVM task/target
    # ids, config). The CLI logs these so a reviewer can see exactly what ran.
    command: Optional[list[str]] = None
    meta: dict[str, Any] = field(default_factory=dict)


class Scanner(Protocol):
    name: str

    def scan(self, target: str, **kwargs) -> ScanResult: ...
