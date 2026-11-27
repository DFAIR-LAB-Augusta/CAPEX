from __future__ import annotations

import re

from pathlib import Path

from capex.models import CaptureConfig, CommandAttackConfig, DeviceConfig
from capex.paths import build_ground_truth_path, build_log_path, build_pcap_path, new_session_id
from capex.services.capture_session import CaptureSession


class _FakeProcess:
    returncode = None

    def poll(self):
        return self.returncode

    def communicate(self):
        return '', ''

    def terminate(self) -> None:
        pass

    def wait(self, timeout=None):
        self.returncode = -15
        return self.returncode


class _FakeRunner:
    def run(self, args, *, check=True, cwd=None):
        pass

    def popen(self, args, *, cwd=None):
        return _FakeProcess()


def test_new_session_id_is_distinct_and_filename_safe() -> None:
    ids = [new_session_id() for _ in range(5)]

    assert len(set(ids)) == 5
    assert all(re.fullmatch(r'\d{8}T\d{6}Z-[0-9a-f]{6}', session_id) for session_id in ids)


def test_path_builders_embed_session_id() -> None:
    config = CaptureConfig(output_dir=Path('data/raw'), log_dir=Path('data/logs'))
    device = DeviceConfig(name='dev1', ip='192.168.1.1')

    assert build_pcap_path(config=config, device=device, session_id='S') == Path('data/raw/dev1_S_flow.pcap')
    assert build_log_path(config=config, device=device, session_id='S') == Path('data/logs/dev1_S_CE.txt')
    assert build_ground_truth_path(config=config, device=device, session_id='S') == Path('data/logs/dev1_S_GT.csv')


def test_two_sessions_for_one_device_do_not_overwrite_logs(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr('capex.services.capture_session.time.sleep', lambda _seconds: None)
    monkeypatch.setattr('capex.capture.time.sleep', lambda _seconds: None)

    device = DeviceConfig(name='dev1', ip='192.168.1.1')
    config = CaptureConfig(duration_seconds=2, safe_period_seconds=1, output_dir=tmp_path, log_dir=tmp_path)
    session = CaptureSession(runner=_FakeRunner(), config=config)
    attack = CommandAttackConfig(name='a', label='A', repeats=1, command=['echo', 'hi'])

    session.run(device=device, attacks=[attack])
    (first,) = tmp_path.glob('dev1_*_CE.txt')
    first_bytes = first.read_bytes()

    session.run(device=device, attacks=[attack])
    logs = list(tmp_path.glob('dev1_*_CE.txt'))

    assert len(logs) == 2
    assert first.read_bytes() == first_bytes
