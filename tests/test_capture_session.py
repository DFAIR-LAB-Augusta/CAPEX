from __future__ import annotations

from capex.attacks import hulk
from capex.models import CaptureConfig, CommandAttackConfig, DeviceConfig, HulkAttackConfig
from capex.services.capture_session import CaptureSession


class _FakeTcpdumpProcess:
    def __init__(self) -> None:
        self.returncode = None
        self.terminated = False

    def poll(self):
        return self.returncode

    def communicate(self):
        return '', ''

    def terminate(self) -> None:
        self.terminated = True

    def wait(self, timeout=None):
        self.returncode = -15
        return self.returncode


class _RecordingRunner:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.popen_calls: list[list[str]] = []
        self.processes: list[_FakeTcpdumpProcess] = []

    def run(self, args, *, check=True, cwd=None):
        self.calls.append(list(args))

    def popen(self, args, *, cwd=None):
        self.popen_calls.append(list(args))
        process = _FakeTcpdumpProcess()
        self.processes.append(process)
        return process


def test_run_attacks_invokes_each_attack_exactly_its_configured_repeats(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr('capex.services.capture_session.time.sleep', lambda _seconds: None)

    device = DeviceConfig(name='dev1', ip='192.168.1.1')
    config = CaptureConfig(
        duration_seconds=100,
        safe_period_seconds=10,
        output_dir=tmp_path,
        log_dir=tmp_path,
    )
    runner = _RecordingRunner()
    session = CaptureSession(runner=runner, config=config)

    few_repeats = CommandAttackConfig(
        name='few',
        label='few',
        repeats=2,
        command=['echo', 'few'],
    )
    many_repeats = CommandAttackConfig(
        name='many',
        label='many',
        repeats=4,
        command=['echo', 'many'],
    )

    log_path = tmp_path / 'dev1_CE.txt'
    session._run_attacks(
        device=device,
        attacks=[few_repeats, many_repeats],
        log_path=log_path,
    )

    few_calls = [call for call in runner.calls if call[1] == 'few']
    many_calls = [call for call in runner.calls if call[1] == 'many']

    assert len(few_calls) == 2
    assert len(many_calls) == 4

    # The capture session is the sole writer of the attack log - one line
    # per scheduled attack, in its own format, with no separate writes
    # from the executors themselves.
    log_lines = log_path.read_text(encoding='utf-8').splitlines()
    assert len(log_lines) == 6
    assert all(line.startswith('Attack: ') for line in log_lines)


def test_run_attacks_warns_and_returns_early_when_no_attacks_enabled(tmp_path, caplog) -> None:
    device = DeviceConfig(name='dev1', ip='192.168.1.1')
    config = CaptureConfig(output_dir=tmp_path, log_dir=tmp_path)
    session = CaptureSession(runner=_RecordingRunner(), config=config)

    disabled = CommandAttackConfig(name='a', label='A', enabled=False, command=['echo', 'hi'])

    log_path = tmp_path / 'dev1_CE.txt'
    with caplog.at_level('WARNING'):
        session._run_attacks(device=device, attacks=[disabled], log_path=log_path)

    assert 'No enabled attacks for device dev1' in caplog.text
    assert not log_path.exists()


def test_run_starts_and_stops_tcpdump_capture(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr('capex.services.capture_session.time.sleep', lambda _seconds: None)
    monkeypatch.setattr('capex.capture.time.sleep', lambda _seconds: None)

    device = DeviceConfig(name='dev1', ip='192.168.1.1')
    config = CaptureConfig(
        duration_seconds=2,
        safe_period_seconds=1,
        output_dir=tmp_path,
        log_dir=tmp_path,
    )
    runner = _RecordingRunner()
    session = CaptureSession(runner=runner, config=config)

    attack = CommandAttackConfig(name='a', label='A', repeats=1, command=['echo', 'hi'])

    session.run(device=device, attacks=[attack])

    assert len(runner.popen_calls) == 1
    assert runner.popen_calls[0][0] == 'tcpdump'
    assert str(tmp_path / 'dev1_flow.pcap') in runner.popen_calls[0]

    process = runner.processes[0]
    assert process.terminated is True

    assert (tmp_path / 'dev1_CE.txt').exists()


def test_run_attacks_appends_executor_detail_to_session_log_line(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr('capex.services.capture_session.time.sleep', lambda _seconds: None)
    monkeypatch.setattr(hulk.time, 'sleep', lambda _seconds: None)
    monkeypatch.setattr(hulk.urllib.request, 'urlopen', lambda request, timeout=None: None)

    device = DeviceConfig(name='dev1', ip='192.168.1.1')
    config = CaptureConfig(
        duration_seconds=100,
        safe_period_seconds=10,
        output_dir=tmp_path,
        log_dir=tmp_path,
    )
    session = CaptureSession(runner=_RecordingRunner(), config=config)

    attack = HulkAttackConfig(name='hulk', label='HULK', repeats=1, thread_count=1, duration_seconds=1)

    log_path = tmp_path / 'dev1_CE.txt'
    session._run_attacks(device=device, attacks=[attack], log_path=log_path)

    (line,) = log_path.read_text(encoding='utf-8').splitlines()
    assert line.startswith('Attack: HULK, ')
    assert 'requests=' in line
