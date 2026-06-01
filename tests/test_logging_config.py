"""Tests for logging configuration: healthcheck log level and colorlog fallback."""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch


def test_healthcheck_is_completely_suppressed(caplog):
    """Docker healthcheck hits must be completely dropped — no log at any level.

    Logging even at DEBUG floods Portainer when LOG_LEVEL=DEBUG is used for
    troubleshooting. The filter must return False and emit nothing.
    """
    from app.config import _HealthcheckFilter

    filt = _HealthcheckFilter()

    record = logging.LogRecord(
        name="uvicorn.access",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg='127.0.0.1:0 - "GET /jwks.json HTTP/1.1" 200',
        args=(),
        exc_info=None,
    )

    with caplog.at_level(logging.DEBUG):
        result = filt.filter(record)

    assert result is False
    # Nothing logged — not even at DEBUG
    assert caplog.records == []


def test_non_healthcheck_access_log_passes_through():
    """Normal access log entries must not be swallowed by the healthcheck filter."""
    from app.config import _HealthcheckFilter

    filt = _HealthcheckFilter()
    record = logging.LogRecord(
        name="uvicorn.access",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg='10.0.0.1:0 - "POST /webhook/authentik HTTP/1.1" 200',
        args=(),
        exc_info=None,
    )
    assert filt.filter(record) is True


def test_logging_without_colorlog_still_starts(monkeypatch):
    """configure_logging() must not raise when colorlog is not installed."""
    mock_settings = MagicMock(
        log_level="INFO",
        ssf_log_color=True,  # color requested but colorlog absent
    )
    monkeypatch.setattr("app.config.settings", mock_settings)

    with patch.dict("sys.modules", {"colorlog": None}):
        from app.config import configure_logging
        configure_logging()  # must not raise


def test_logging_color_disabled_uses_plain_formatter(monkeypatch):
    """When SSF_LOG_COLOR=false, plain text formatter is used regardless of colorlog."""
    mock_settings = MagicMock(log_level="INFO", ssf_log_color=False)
    monkeypatch.setattr("app.config.settings", mock_settings)

    from app.config import configure_logging
    configure_logging()  # must not raise; no colorlog import attempted
