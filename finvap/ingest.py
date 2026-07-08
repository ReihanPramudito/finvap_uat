"""Persist a ``ScanResult`` into the database.

Assets are upserted by IP so repeated scans enrich the same asset rather than
duplicating it (and crucially, preserve the context tags a user has set).
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlmodel import select

from .db import get_session
from .models import Asset, Finding, Port, Scan
from .scanners.base import ScanResult


def ingest(result: ScanResult, raw_output_path: str | None = None) -> Scan:
    with get_session() as session:
        scan = Scan(
            target=result.target,
            tool=result.tool,
            finished_at=datetime.now(timezone.utc),
            raw_output_path=raw_output_path,
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)

        asset_ids: dict[str, int] = {}

        def upsert_asset(ip: str, hostname=None, os=None) -> int:
            if ip in asset_ids:
                return asset_ids[ip]
            asset = session.exec(select(Asset).where(Asset.ip_address == ip)).first()
            if asset is None:
                asset = Asset(ip_address=ip, hostname=hostname, os=os)
                session.add(asset)
            else:  # enrich, never clobber existing values or tags
                asset.hostname = asset.hostname or hostname
                asset.os = asset.os or os
            session.commit()
            session.refresh(asset)
            asset_ids[ip] = asset.id
            return asset.id

        for a in result.assets:
            upsert_asset(a.ip_address, a.hostname, a.os)

        for p in result.ports:
            aid = upsert_asset(p.ip_address)
            existing = session.exec(
                select(Port).where(
                    Port.asset_id == aid, Port.port == p.port, Port.protocol == p.protocol
                )
            ).first()
            if existing:
                existing.state = p.state or existing.state
                existing.service = p.service or existing.service
                existing.product = p.product or existing.product
                existing.version = p.version or existing.version
                session.add(existing)
            else:
                session.add(Port(
                    asset_id=aid, port=p.port, protocol=p.protocol, state=p.state,
                    service=p.service, product=p.product, version=p.version,
                ))

        for f in result.findings:
            aid = upsert_asset(f.ip_address)
            session.add(Finding(
                scan_id=scan.id, asset_id=aid, tool=f.tool, name=f.name,
                description=f.description, summary=f.summary, impact=f.impact,
                affected=f.affected, port=f.port, protocol=f.protocol,
                cve=f.cve, cvss_base=f.cvss_base, cvss_version=f.cvss_version,
                cvss_vector=f.cvss_vector,
                severity=f.severity, qod=f.qod, solution=f.solution,
                references=f.references,
            ))

        session.commit()
        session.refresh(scan)
        return scan
