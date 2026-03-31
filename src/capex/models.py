from __future__ import annotations

from pathlib import Path
from typing import Final

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, PositiveInt


class DeviceConfig(BaseModel):
    model_config = ConfigDict(extra='forbid')

    name: str = Field(min_length=1)
    ip: IPvAnyAddress
    enabled: bool = True


class AttackConfig(BaseModel):
    model_config = ConfigDict(extra='forbid')

    name: str = Field(min_length=1)
    label: str = Field(min_length=1)
    command: list[str] = Field(min_length=1)
    repeats: PositiveInt = 3
    enabled: bool = True


class CaptureConfig(BaseModel):
    model_config = ConfigDict(extra='forbid')

    duration_seconds: PositiveInt = 8 * 60 * 60
    safe_period_seconds: PositiveInt = 15 * 60
    output_dir: Path = Path('data/raw')
    log_dir: Path = Path('data/logs')
    tcpdump_binary: str = 'tcpdump'


class DeviceFile(BaseModel):
    devices: list[DeviceConfig]


class AttackFile(BaseModel):
    attacks: list[AttackConfig]


DEFAULT_PCAP_SUFFIX: Final[str] = '_flow.pcap'
DEFAULT_LOG_SUFFIX: Final[str] = '_CE.txt'
