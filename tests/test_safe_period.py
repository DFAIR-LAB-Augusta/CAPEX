from __future__ import annotations

import csv

import pytest

from capex.exceptions import ValidationError
from capex.models import CaptureConfig, CommandAttackConfig, DeviceConfig
from capex.scheduler import build_schedule
from capex.services.capture_session import CaptureSession
from capex.validation import validate_capture_config


class _Process:
    def poll(self):
        return None

    def communicate(self):
        return '', ''

    def terminate(self) -> None:
        pass

    def wait(self, timeout=None):
        return 0


class _Runner:
    def run(self, args, *, check=True, cwd=None):
        return None

    def popen(self, args, *, cwd=None):
        return _Process()


def test_build_schedule_shifts_offsets_by_start_offset() -> None:
    base = build_schedule(repeats_per_attack=[3, 2], allowed_duration_seconds=60)
    shifted = build_schedule(repeats_per_attack=[3, 2], allowed_duration_seconds=60, start_offset_seconds=15)

    assert [item.offset_seconds + 15 for item in base] == [item.offset_seconds for item in shifted]


def test_run_attacks_start_offsets_respect_safe_period(tmp_path, monkeypatch) -> None:
    clock = [1000.0]
    monkeypatch.setattr('capex.services.capture_session.time.time', lambda: clock[0])
    monkeypatch.setattr(
        'capex.services.capture_session.time.sleep', lambda seconds: clock.__setitem__(0, clock[0] + seconds)
    )

    duration, safe = 100, 10
    config = CaptureConfig(duration_seconds=duration, safe_period_seconds=safe, output_dir=tmp_path, log_dir=tmp_path)
    session = CaptureSession(runner=_Runner(), config=config)
    device = DeviceConfig(name='dev1', ip='192.168.1.1')
    attack = CommandAttackConfig(name='a', label='A', repeats=4, command=['echo', 'hi'])
    gt_path = tmp_path / 'gt.csv'

    session._run_attacks(
        device=device, attacks=[attack], log_path=tmp_path / 'log.txt', ground_truth_path=gt_path, session_id='S1'
    )

    with gt_path.open(encoding='utf-8', newline='') as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 4
    for row in rows:
        offset = float(row['start_unix']) - 1000.0
        assert safe <= offset < duration - safe


def test_validate_capture_config_rejects_double_safe_period_at_limit() -> None:
    config = CaptureConfig(duration_seconds=100, safe_period_seconds=50)

    with pytest.raises(ValidationError, match='safe_period_seconds=50'):
        validate_capture_config(config)


def test_validate_capture_config_accepts_just_under_limit() -> None:
    validate_capture_config(CaptureConfig(duration_seconds=100, safe_period_seconds=49))
