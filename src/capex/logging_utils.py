from __future__ import annotations

import logging


def configure_logging(*, verbose: bool = False) -> None:
    """Configure application-wide logging.

    Parameters
    ----------
    verbose:
        If True, enable DEBUG logging. Otherwise use INFO.
    """
    level = logging.DEBUG if verbose else logging.INFO

    logging.basicConfig(
        level=level,
        format='%(asctime)s %(levelname)s %(name)s: %(message)s',
    )


def get_logger(name: str) -> logging.Logger:
    """Return a standard library logger."""
    return logging.getLogger(name)
