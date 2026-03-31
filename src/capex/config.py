from __future__ import annotations

from typing import TYPE_CHECKING, Any

import yaml

from capex.models import AttackFile, CaptureConfig, DeviceFile

if TYPE_CHECKING:
    from pathlib import Path


def _load_yaml(path: Path) -> dict[str, Any]:
    with path.open('r', encoding='utf-8') as handle:
        data = yaml.safe_load(handle)

    if not isinstance(data, dict):
        msg = f'Expected mapping at top level in {path}'
        raise ValueError(msg)

    return data


def load_devices(path: Path) -> DeviceFile:
    return DeviceFile.model_validate(_load_yaml(path))


def load_attacks(path: Path) -> AttackFile:
    return AttackFile.model_validate(_load_yaml(path))


def ensure_directories(config: CaptureConfig) -> None:
    config.output_dir.mkdir(parents=True, exist_ok=True)
    config.log_dir.mkdir(parents=True, exist_ok=True)
