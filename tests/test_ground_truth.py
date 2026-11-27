from __future__ import annotations

import csv

import pytest

from capex.models import CaptureConfig, CommandAttackConfig, DeviceConfig
from capex.services.capture_session import CaptureSession


class _Runner:
    def __init__(self, *, fail_on: str | None = None) -> None:
        self.fail_on = fail_on

    def run(self, args, *, check=True, cwd=None):
        if self.fail_on and self.fail_on in args:
            raise RuntimeError('boom')

    def popen(self, args, *, cwd=None):
        raise AssertionError('not used')


def _session(tmp_path, runner):
    config = CaptureConfig(duration_seconds=100, safe_period_seconds=10, output_dir=tmp_path, log_dir=tmp_path)
    return CaptureSession(runner=runner, config=config)


def _attacks():
    return [
        CommandAttackConfig(name='a', label='A', repeats=1, command=['echo', 'a']),
        CommandAttackConfig(name='b', label='B', repeats=1, command=['echo', 'b']),
    ]


def test_ground_truth_csv_has_one_row_per_attack(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr('capex.services.capture_session.time.sleep', lambda _seconds: None)
    device = DeviceConfig(name='dev1', ip='192.168.1.9')
    gt_path = tmp_path / 'gt.csv'
    log_path = tmp_path / 'log.txt'

    _session(tmp_path, _Runner())._run_attacks(
        device=device, attacks=_attacks(), log_path=log_path, ground_truth_path=gt_path, session_id='SID'
    )

    lines = gt_path.read_text(encoding='utf-8').splitlines()
    assert lines[0] == 'session_id,device,target_ip,label,attempt,start_unix,end_unix'
    rows = list(csv.DictReader(lines))
    assert [row['label'] for row in rows] == ['A', 'B']
    for row in rows:
        assert row['session_id'] == 'SID'
        assert row['device'] == 'dev1'
        assert row['target_ip'] == '192.168.1.9'
        assert float(row['end_unix']) >= float(row['start_unix'])

    for line in log_path.read_text(encoding='utf-8').splitlines():
        assert ', End Unix Time: ' in line
        assert ', Target IP: 192.168.1.9, Session: SID' in line


def test_ground_truth_row_written_when_executor_raises(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr('capex.services.capture_session.time.sleep', lambda _seconds: None)
    device = DeviceConfig(name='dev1', ip='192.168.1.9')
    gt_path = tmp_path / 'gt.csv'

    session = _session(tmp_path, _Runner(fail_on='a'))
    with pytest.raises(RuntimeError, match='boom'):
        session._run_attacks(
            device=device,
            attacks=_attacks(),
            log_path=tmp_path / 'log.txt',
            ground_truth_path=gt_path,
            session_id='SID',
        )

    rows = list(csv.DictReader(gt_path.read_text(encoding='utf-8').splitlines()))
    assert len(rows) == 1
    assert rows[0]['label'] == 'A'
    assert float(rows[0]['end_unix']) >= float(rows[0]['start_unix'])
