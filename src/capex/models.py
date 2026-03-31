from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, PositiveInt


class DeviceConfig(BaseModel):
    model_config = ConfigDict(extra='forbid')

    name: str = Field(min_length=1)
    ip: IPvAnyAddress
    enabled: bool = True


class CommandAttackConfig(BaseModel):
    model_config = ConfigDict(extra='forbid')

    kind: Literal['command'] = 'command'
    name: str = Field(min_length=1)
    label: str = Field(min_length=1)
    enabled: bool = True
    repeats: PositiveInt = 3
    command: list[str] = Field(min_length=1)


class PlaceholderAttackConfig(BaseModel):
    model_config = ConfigDict(extra='forbid')

    kind: Literal['placeholder'] = 'placeholder'
    name: str = Field(min_length=1)
    label: str = Field(min_length=1)
    enabled: bool = False
    repeats: PositiveInt = 1
    reason: str = Field(min_length=1)


AttackConfig = CommandAttackConfig | PlaceholderAttackConfig


class AttackFile(BaseModel):
    model_config = ConfigDict(extra='forbid')
    attacks: list[AttackConfig]


class CaptureConfig(BaseModel):
    model_config = ConfigDict(extra='forbid')

    duration_seconds: PositiveInt = 8 * 60 * 60
    safe_period_seconds: PositiveInt = 15 * 60
    output_dir: Path = Path('data/raw')
    log_dir: Path = Path('data/logs')
    tcpdump_binary: str = 'tcpdump'


class DeviceFile(BaseModel):
    devices: list[DeviceConfig]
