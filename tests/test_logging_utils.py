from __future__ import annotations

import logging

from capex.logging_utils import configure_logging, get_logger


def test_configure_logging_uses_debug_when_verbose(monkeypatch) -> None:
    captured = {}
    monkeypatch.setattr(logging, 'basicConfig', lambda **kwargs: captured.update(kwargs))

    configure_logging(verbose=True)

    assert captured['level'] == logging.DEBUG


def test_configure_logging_uses_info_by_default(monkeypatch) -> None:
    captured = {}
    monkeypatch.setattr(logging, 'basicConfig', lambda **kwargs: captured.update(kwargs))

    configure_logging()

    assert captured['level'] == logging.INFO


def test_get_logger_returns_named_logger() -> None:
    logger = get_logger('capex.test')

    assert isinstance(logger, logging.Logger)
    assert logger.name == 'capex.test'
