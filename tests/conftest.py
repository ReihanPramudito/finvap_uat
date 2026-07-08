"""Shared test fixtures.

Auditing (Step 1) writes an event store + AI artifacts under ``config.LOGS_DIR``.
Redirect that to a per-test temp directory automatically so the suite never
touches the real ``data/logs/`` and tests stay isolated from one another.
"""
import pytest

from finvap import config


@pytest.fixture(autouse=True)
def _isolate_audit_logs(tmp_path, monkeypatch):
    logs = tmp_path / "audit-logs"
    monkeypatch.setattr(config, "LOGS_DIR", logs)
    monkeypatch.setattr(config, "AI_LOGS_DIR", logs / "ai")
    # Keep operator preferences + engagement metadata out of the real project root too.
    monkeypatch.setattr(config, "USER_CONFIG_PATH", tmp_path / "finvap.config.json")
    monkeypatch.setattr(config, "ENGAGEMENT_PATH", tmp_path / "finvap.engagement.json")
    # And never see the operator's real cloud credentials — a key saved via the
    # web UI made keyless-provider tests fail and sent live API calls from the
    # suite. Tests that need a key monkeypatch these themselves.
    monkeypatch.setattr(config, "SECRETS_PATH", tmp_path / "finvap.secrets.json")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
