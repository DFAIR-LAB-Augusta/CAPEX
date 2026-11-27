from __future__ import annotations

import secrets

from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from capex.models import CaptureConfig, DeviceConfig


def ensure_directory(path: Path) -> None:
    """Create a directory and its parents if they do not already exist."""
    path.mkdir(parents=True, exist_ok=True)


def ensure_capture_directories(config: CaptureConfig) -> None:
    """Ensure all configured output directories exist."""
    ensure_directory(config.output_dir)
    ensure_directory(config.log_dir)


def new_session_id() -> str:
    """Return a unique, filename-safe session ID: UTC timestamp plus a random suffix."""
    stamp = datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')
    return f'{stamp}-{secrets.token_hex(3)}'


def build_pcap_path(*, config: CaptureConfig, device: DeviceConfig, session_id: str) -> Path:
    """Return the output PCAP path for a device session."""
    return config.output_dir / f'{device.name}_{session_id}_flow.pcap'


def build_log_path(*, config: CaptureConfig, device: DeviceConfig, session_id: str) -> Path:
    """Return the attack log path for a device session."""
    return config.log_dir / f'{device.name}_{session_id}_CE.txt'


def build_ground_truth_path(*, config: CaptureConfig, device: DeviceConfig, session_id: str) -> Path:
    """Return the ground-truth CSV path for a device session."""
    return config.log_dir / f'{device.name}_{session_id}_GT.csv'
