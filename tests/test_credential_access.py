from __future__ import annotations

from pathlib import Path

from capex.attacks import credential_access
from capex.models import DeviceConfig, HydraBruteForceAttackConfig
from capex.runner import CompletedCommand


class _FakeRunner:
    def __init__(self, *, returncode: int = 1) -> None:
        self.calls: list[list[str]] = []
        self.combo_file_content: str | None = None
        self.combo_file_path: Path | None = None
        self._returncode = returncode

    def run(self, args, *, check: bool = True, cwd=None) -> CompletedCommand:
        self.calls.append(list(args))
        combo_path = Path(args[args.index('-C') + 1])
        self.combo_file_path = combo_path
        self.combo_file_content = combo_path.read_text()
        return CompletedCommand(args=tuple(args), returncode=self._returncode, stdout='', stderr='')


def test_hydra_executor_caps_attempts_to_max_attempts() -> None:
    runner = _FakeRunner()
    attack = HydraBruteForceAttackConfig(
        name='hydra_http_default_creds',
        label='Hydra_HTTP_Default_Creds',
        service='http-get',
        port=80,
        username_list=['admin', 'root'],
        password_list=['admin', '1234'],
        max_attempts=3,
    )
    executor = credential_access.HydraBruteForceExecutor(runner=runner, attack=attack)
    device = DeviceConfig(name='dev1', ip='192.168.1.1')

    detail = executor.execute(device=device)

    assert detail == 'attempts=3'
    assert runner.combo_file_content == 'admin:admin\nadmin:1234\nroot:admin\n'


def test_hydra_executor_invokes_hydra_with_expected_args() -> None:
    runner = _FakeRunner()
    attack = HydraBruteForceAttackConfig(
        name='hydra_http_default_creds',
        label='Hydra_HTTP_Default_Creds',
        service='http-get',
        port=8080,
        username_list=['admin'],
        password_list=['admin'],
        tasks=1,
    )
    executor = credential_access.HydraBruteForceExecutor(runner=runner, attack=attack)
    device = DeviceConfig(name='dev1', ip='192.168.1.1')

    executor.execute(device=device)

    call = runner.calls[0]
    assert call[0] == 'hydra'
    assert '-t' in call
    assert call[call.index('-t') + 1] == '1'
    assert '192.168.1.1' in call
    assert 'http-get' in call
    assert '-s' in call
    assert call[call.index('-s') + 1] == '8080'


def test_hydra_executor_cleans_up_combo_file_after_run() -> None:
    runner = _FakeRunner()
    attack = HydraBruteForceAttackConfig(
        name='hydra_http_default_creds',
        label='Hydra_HTTP_Default_Creds',
        service='http-get',
        port=80,
        username_list=['admin'],
        password_list=['admin'],
    )
    executor = credential_access.HydraBruteForceExecutor(runner=runner, attack=attack)
    device = DeviceConfig(name='dev1', ip='192.168.1.1')

    executor.execute(device=device)

    assert runner.combo_file_path is not None
    assert not runner.combo_file_path.exists()
