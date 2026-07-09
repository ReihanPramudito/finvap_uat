"""Nmap scanner: asset discovery + service/version enumeration.

Runs nmap with XML output to stdout and parses it. Uses a TCP connect scan
(``-sT``) by default so it works without root; pass custom args for ``-sS`` etc.
"""
from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET

from .base import DiscoveredAsset, DiscoveredPort, ScanResult

# Unprivileged-friendly defaults: connect scan + version detection.
DEFAULT_ARGS = ["-sT", "-sV", "-T4", "--top-ports", "1000", "-Pn"]

# Host-discovery only (a "what's alive" sweep). Note: NO -Pn here — unlike the
# assessment scan (which force-probes a known target), discovery WANTS nmap to
# decide liveness. On a local subnet nmap uses ARP (most reliable as root);
# otherwise it falls back to TCP/ICMP probes.
DISCOVERY_ARGS = ["-sn", "-T4"]


class NmapScanner:
    name = "nmap"

    def __init__(self, binary: str | None = None, extra_args: list[str] | None = None):
        self.binary = binary or shutil.which("nmap")
        if not self.binary:
            raise RuntimeError("nmap not found on PATH")
        self.extra_args = extra_args

    def scan(self, target: str, **kwargs) -> ScanResult:
        args = self.extra_args if self.extra_args is not None else DEFAULT_ARGS
        cmd = [self.binary, *args, "-oX", "-", *target.split()]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0 and not proc.stdout:
            raise RuntimeError(f"nmap failed: {proc.stderr.strip()}")
        result = self._parse(proc.stdout, target)
        result.command = cmd  # literal argv, for the audit trail
        result.meta = {"returncode": proc.returncode}
        return result

    def discover(self, target: str) -> list[dict]:
        """Host-discovery only: which IPs in `target` are live. Returns a list of
        ``{ip, hostname, mac, vendor, reason}`` for the hosts nmap reports UP.
        Raises RuntimeError if nmap can't run at all."""
        cmd = [self.binary, *DISCOVERY_ARGS, "-oX", "-", *target.split()]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0 and not proc.stdout:
            raise RuntimeError(f"nmap failed: {proc.stderr.strip()}")
        return self._parse_discovery(proc.stdout)

    @staticmethod
    def _parse_discovery(xml_text: str) -> list[dict]:
        hosts: list[dict] = []
        root = ET.fromstring(xml_text)
        for host in root.findall("host"):
            status = host.find("status")
            if status is not None and status.get("state") != "up":
                continue
            ip = next((a.get("addr") for a in host.findall("address")
                       if a.get("addrtype") in ("ipv4", "ipv6")), None)
            if not ip:
                continue
            mac = next((a for a in host.findall("address")
                        if a.get("addrtype") == "mac"), None)
            hn = host.find("hostnames/hostname")
            hosts.append({
                "ip": ip,
                "hostname": hn.get("name") if hn is not None else None,
                "mac": mac.get("addr") if mac is not None else None,
                "vendor": mac.get("vendor") if mac is not None else None,
                "reason": status.get("reason") if status is not None else None,
            })
        return hosts

    @staticmethod
    def _parse(xml_text: str, target: str) -> ScanResult:
        result = ScanResult(tool="nmap", target=target, raw_output=xml_text)
        root = ET.fromstring(xml_text)
        for host in root.findall("host"):
            status = host.find("status")
            if status is not None and status.get("state") != "up":
                continue

            ip = next(
                (a.get("addr") for a in host.findall("address")
                 if a.get("addrtype") in ("ipv4", "ipv6")),
                None,
            )
            if not ip:
                continue

            hn = host.find("hostnames/hostname")
            osmatch = host.find("os/osmatch")
            result.assets.append(DiscoveredAsset(
                ip_address=ip,
                hostname=hn.get("name") if hn is not None else None,
                os=osmatch.get("name") if osmatch is not None else None,
            ))

            for port in host.findall("ports/port"):
                state = port.find("state")
                if state is not None and state.get("state") != "open":
                    continue
                svc = port.find("service")
                result.ports.append(DiscoveredPort(
                    ip_address=ip,
                    port=int(port.get("portid")),
                    protocol=port.get("protocol", "tcp"),
                    state=state.get("state") if state is not None else None,
                    service=svc.get("name") if svc is not None else None,
                    product=svc.get("product") if svc is not None else None,
                    version=svc.get("version") if svc is not None else None,
                ))
        return result
