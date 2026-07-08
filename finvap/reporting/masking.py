"""PII masking for LLM calls (Objective 4, privacy).

Before any finding/asset text is sent to an LLM — local *or* cloud — real
identifiers (IP addresses, hostnames) are swapped for stable placeholders
(``ASSET-1``, ``HOST-1``). The placeholder->real map is held only in-process and
applied in reverse at render time, so the editable Markdown and the final
PDF/DOCX show real values while the model (especially a cloud one) only ever
saw ``ASSET-1``. Data-minimisation by default; nothing leaves the host
un-masked.
"""
from __future__ import annotations

import re

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class Masker:
    def __init__(self) -> None:
        self._to_placeholder: dict[str, str] = {}
        self._to_real: dict[str, str] = {}
        self._asset_n = 0
        self._host_n = 0

    def _add(self, real: str, placeholder: str) -> None:
        self._to_placeholder[real] = placeholder
        self._to_real[placeholder] = real

    def register_asset(self, ip: str | None, hostname: str | None = None) -> str:
        """Assign stable placeholders for an asset's IP (+ hostname). Returns the
        IP placeholder (or the hostname's if no IP)."""
        ph = None
        if ip and ip not in self._to_placeholder:
            self._asset_n += 1
            self._add(ip, f"ASSET-{self._asset_n}")
        if ip:
            ph = self._to_placeholder[ip]
        if hostname and hostname not in self._to_placeholder:
            self._host_n += 1
            self._add(hostname, f"HOST-{self._host_n}")
            ph = ph or self._to_placeholder[hostname]
        return ph or "ASSET-?"

    def mask(self, text: str | None) -> str:
        """Replace every registered real value, then any remaining IPv4, with a
        placeholder. Longest reals first so substrings can't partially match."""
        if not text:
            return ""
        out = text
        for real in sorted(self._to_placeholder, key=len, reverse=True):
            out = out.replace(real, self._to_placeholder[real])
        # Catch stray IPs that weren't registered as assets (e.g. in scan text).
        out = _IPV4.sub(self._mask_stray_ip, out)
        return out

    def _mask_stray_ip(self, m: re.Match) -> str:
        ip = m.group(0)
        if ip not in self._to_placeholder:
            self._asset_n += 1
            self._add(ip, f"ASSET-{self._asset_n}")
        return self._to_placeholder[ip]

    def unmask(self, text: str | None) -> str:
        """Restore real values. Longest placeholders first (ASSET-10 before ASSET-1)."""
        if not text:
            return ""
        out = text
        for ph in sorted(self._to_real, key=len, reverse=True):
            out = out.replace(ph, self._to_real[ph])
        return out

    @property
    def map(self) -> dict[str, str]:
        """placeholder -> real (kept local; never sent anywhere)."""
        return dict(self._to_real)
