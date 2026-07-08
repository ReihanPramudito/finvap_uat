"""Import findings from a Tenable Nessus ``.nessus`` export.

A ``.nessus`` file (``NessusClientData_v2``) is XML laid out as
``Report > ReportHost > ReportItem``. Each ``ReportItem`` maps to a
:class:`DiscoveredFinding`, so an imported scan reuses :mod:`finvap.ingest`
unchanged and then flows through scoring (Obj 3), regulatory mapping (Obj 1) and
reporting (Obj 4) exactly like a GVM scan. This lets an operator who already
runs Nessus get FinVAP's localised regulatory layer without standing up GVM —
and gives a fast, offline alternative input for a live demo.

The one detail that matters for Obj 3 is the CVSS **vector**: it is normalised
to the exact shape :func:`finvap.risk.convert.parse_vector` expects (v3 prefixed
``CVSS:3.x/…``; v2 bare, with Nessus's ``CVSS2#`` prefix stripped).
"""
from __future__ import annotations

from pathlib import Path

from lxml import etree

from .base import DiscoveredAsset, DiscoveredFinding, DiscoveredPort, ScanResult
from .gvm_scanner import cvss_to_severity  # shared, tested CVSS->label banding

# Nessus's numeric @severity attribute -> our label. Used only as a fallback for
# plugins that carry no CVSS base score (e.g. purely informational plugins).
_NESSUS_SEVERITY = {"0": "Log", "1": "Low", "2": "Medium", "3": "High", "4": "Critical"}
_RISK_FACTOR = {"none": "Log", "low": "Low", "medium": "Medium",
                "high": "High", "critical": "Critical"}


class NessusImportError(RuntimeError):
    """The .nessus file could not be read or wasn't a recognised Nessus export."""


class NessusImporter:
    name = "nessus"

    def scan(self, target: str, **kwargs) -> ScanResult:
        """Scanner-protocol parity: for an importer the ``target`` is the file."""
        return self.import_file(target)

    def import_file(self, path: str | Path) -> ScanResult:
        path = Path(path)
        if not path.exists():
            raise NessusImportError(f"No such file: {path}")
        try:
            root = etree.parse(str(path)).getroot()
        except etree.XMLSyntaxError as e:
            raise NessusImportError(f"Not valid XML: {e}") from e
        if root.tag != "NessusClientData_v2" and root.find(".//Report") is None:
            raise NessusImportError(
                "Not a Nessus export (expected NessusClientData_v2 with a <Report>)."
            )
        result = self._parse(root, label=path.name)
        result.raw_output_path = str(path)  # provenance: point at the source file
        return result

    @staticmethod
    def _parse(root, label: str) -> ScanResult:
        result = ScanResult(tool="nessus", target=label)
        seen: set[str] = set()
        for host in root.findall(".//ReportHost"):
            props = _host_properties(host)
            ip = props.get("host-ip") or host.get("name")
            if not ip:
                continue
            if ip not in seen:
                seen.add(ip)
                result.assets.append(DiscoveredAsset(
                    ip_address=ip,
                    # FQDN/rDNS where present; fall back to the NetBIOS name so
                    # Windows hosts (common in credentialed scans) aren't nameless.
                    hostname=(props.get("host-fqdn") or props.get("host-rdns")
                              or props.get("netbios-name")),
                    os=props.get("operating-system"),
                ))
            for item in host.findall("ReportItem"):
                result.findings.append(_parse_item(item, ip))
                port = _port_from_item(item, ip)
                if port is not None:
                    result.ports.append(port)
        return result


def _parse_item(item, ip: str) -> DiscoveredFinding:
    cves = [e.text.strip() for e in item.findall("cve") if e.text and e.text.strip()]
    version, vector, base = _cvss(item)
    severity = (
        cvss_to_severity(base)                                  # band the CVSS base (consistent)
        or _NESSUS_SEVERITY.get(item.get("severity") or "")     # else Nessus's own band
        or _RISK_FACTOR.get((item.findtext("risk_factor") or "").strip().lower())
    )
    return DiscoveredFinding(
        ip_address=ip,
        name=item.get("pluginName") or "Unnamed finding",
        tool="nessus",
        description=item.findtext("description"),
        summary=item.findtext("synopsis"),
        port=_to_int(item.get("port")) or None,  # port 0 == host-level, not a port
        protocol=item.get("protocol"),
        cve=",".join(cves) or None,
        cvss_base=base,
        cvss_version=version,
        cvss_vector=vector,
        severity=severity,
        solution=item.findtext("solution"),
        references=_references(item, cves),
    )


def _cvss(item) -> tuple[str | None, str | None, float | None]:
    """Pick the best CVSS data: prefer v3 over v2; normalise the vector.

    Returns ``(version, vector, base_score)`` where version is ``"3.1"`` for any
    v3 vector and ``"2.0"`` for v2 (matching the GVM scanner's convention; the
    real sub-version stays in the vector prefix, which the risk engine reads).
    """
    v3_vec = (item.findtext("cvss3_vector") or "").strip()
    v3_base = _to_float(item.findtext("cvss3_base_score"))
    if v3_vec or v3_base is not None:
        return "3.1", (_normalise_v3(v3_vec) if v3_vec else None), v3_base
    v2_vec = (item.findtext("cvss_vector") or "").strip()
    v2_base = _to_float(item.findtext("cvss_base_score"))
    if v2_vec or v2_base is not None:
        return "2.0", (_normalise_v2(v2_vec) if v2_vec else None), v2_base
    return None, None, None


def _normalise_v3(vec: str) -> str:
    # Nessus normally emits "CVSS:3.0/AV:…"; older exports may drop the prefix.
    return vec if vec.upper().startswith("CVSS:") else f"CVSS:3.0/{vec}"


def _normalise_v2(vec: str) -> str:
    # Nessus prefixes v2 vectors with "CVSS2#"; parse_vector wants them bare.
    return vec.split("#", 1)[1] if "#" in vec else vec


def _port_from_item(item, ip: str) -> DiscoveredPort | None:
    port = _to_int(item.get("port"))
    if not port:  # 0 or missing -> host-level finding, not an open port
        return None
    return DiscoveredPort(
        ip_address=ip, port=port, protocol=item.get("protocol") or "tcp",
        state="open", service=item.get("svc_name") or None,
    )


def _host_properties(host) -> dict[str, str]:
    out: dict[str, str] = {}
    hp = host.find("HostProperties")
    if hp is not None:
        for tag in hp.findall("tag"):
            name = tag.get("name")
            if name and tag.text and tag.text.strip():
                out[name] = tag.text.strip()
    return out


def _references(item, cves: list[str]) -> str | None:
    lines = list(cves)
    for tag in ("see_also", "xref"):
        for e in item.findall(tag):
            if e.text and e.text.strip():
                lines.extend(s for s in e.text.strip().splitlines() if s.strip())
    return "\n".join(lines) or None


def _to_int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _to_float(value) -> float | None:
    try:
        f = float(value)
        return f if f >= 0 else None
    except (TypeError, ValueError):
        return None
