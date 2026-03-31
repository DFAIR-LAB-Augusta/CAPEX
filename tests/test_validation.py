from __future__ import annotations

import pytest

from capex.exceptions import ValidationError
from capex.models import CaptureConfig
from capex.validation import validate_capture_config


def test_validate_capture_config_rejects_large_safe_period() -> None:
    config = CaptureConfig(
        duration_seconds=100,
        safe_period_seconds=100,
    )

    with pytest.raises(ValidationError):
        validate_capture_config(config)
