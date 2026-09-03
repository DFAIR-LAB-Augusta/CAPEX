from __future__ import annotations

from capex.models import CaptureConfig, CommandAttackConfig, DeviceConfig
from capex.services.capture_session import CaptureSession


class _RecordingRunner:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def run(self, args, *, check=True, cwd=None):
        self.calls.append(list(args))


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
