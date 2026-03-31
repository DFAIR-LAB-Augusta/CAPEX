from __future__ import annotations

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


def build_pcap_path(*, config: CaptureConfig, device: DeviceConfig) -> Path:
    """Return the output PCAP path for a device."""
    return config.output_dir / f'{device.name}_flow.pcap'


def build_log_path(*, config: CaptureConfig, device: DeviceConfig) -> Path:
    """Return the attack log path for a device."""
    return config.log_dir / f'{device.name}_CE.txt'
