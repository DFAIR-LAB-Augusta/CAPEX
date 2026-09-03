from __future__ import annotations

import subprocess

import pytest

from capex.attacks import arp
from capex.exceptions import AttackExecutionError
from capex.models import ArpSpoofAttackConfig, DeviceConfig


class _FakeProcess:
    def __init__(self, *, exited: bool = False, returncode: int = 1, stderr: str = '') -> None:
        self._exited = exited
        self.returncode = returncode if exited else None
        self._stderr = stderr
        self.terminate_called = False
        self.kill_called = False
        self._wait_calls = 0
        self.timeout_on_first_wait = False

    def poll(self) -> int | None:
        return self.returncode

    def communicate(self) -> tuple[str, str]:
        return '', self._stderr

    def terminate(self) -> None:
        self.terminate_called = True

    def kill(self) -> None:
        self.kill_called = True
        self.returncode = -9

    def wait(self, timeout: float | None = None) -> int:
        self._wait_calls += 1
        if self.timeout_on_first_wait and self._wait_calls == 1:
            raise subprocess.TimeoutExpired(cmd='arpspoof', timeout=timeout or 0)
        self.returncode = self.returncode if self.returncode is not None else -15
        return self.returncode


class _FakeRunner:
    def __init__(self, process: _FakeProcess | list[_FakeProcess]) -> None:
        self._processes = process if isinstance(process, list) else [process]
        self.popen_args: list[str] | None = None
        self.popen_calls: list[list[str]] = []

    def popen(self, args, *, cwd=None):
        self.popen_args = list(args)
        self.popen_calls.append(list(args))
        index = len(self.popen_calls) - 1
        return self._processes[index] if index < len(self._processes) else self._processes[-1]


def test_arp_spoof_executor_runs_for_duration_then_terminates(monkeypatch) -> None:
    process = _FakeProcess(exited=False)
    runner = _FakeRunner(process)
    monkeypatch.setattr(arp.time, 'sleep', lambda seconds: None)

    device = DeviceConfig(name='dev1', ip='192.168.1.1')
    attack = ArpSpoofAttackConfig(
        name='arp_spoof',
        label='ARP_Spoof',
        interface='eth0',
        gateway_ip='192.168.1.1',
        duration_seconds=30,
    )
    executor = arp.ArpSpoofExecutor(runner=runner, attack=attack)

    detail = executor.execute(device=device)

    assert runner.popen_args == ['arpspoof', '-i', 'eth0', '-t', '192.168.1.1', '192.168.1.1']
    assert process.terminate_called is True
    assert process.kill_called is False
    assert detail == 'duration_seconds=30'


def test_arp_spoof_executor_raises_when_process_exits_immediately(monkeypatch) -> None:
    process = _FakeProcess(exited=True, returncode=1, stderr='arpspoof: eth9: No such device exists')
    runner = _FakeRunner(process)
    monkeypatch.setattr(arp.time, 'sleep', lambda seconds: None)

    device = DeviceConfig(name='dev1', ip='192.168.1.1')
    attack = ArpSpoofAttackConfig(name='arp_spoof', label='ARP_Spoof', interface='eth9', gateway_ip='192.168.1.1')
    executor = arp.ArpSpoofExecutor(runner=runner, attack=attack)

    with pytest.raises(AttackExecutionError, match='No such device exists'):
        executor.execute(device=device)


def test_arp_spoof_executor_kills_process_that_does_not_terminate_in_time(monkeypatch) -> None:
    process = _FakeProcess(exited=False)
    process.timeout_on_first_wait = True
    runner = _FakeRunner(process)
    monkeypatch.setattr(arp.time, 'sleep', lambda seconds: None)

    device = DeviceConfig(name='dev1', ip='192.168.1.1')
    attack = ArpSpoofAttackConfig(name='arp_spoof', label='ARP_Spoof', interface='eth0', gateway_ip='192.168.1.1')
    executor = arp.ArpSpoofExecutor(runner=runner, attack=attack)

    executor.execute(device=device)

    assert process.terminate_called is True
    assert process.kill_called is True


def test_arp_spoof_executor_bidirectional_starts_both_directions(monkeypatch) -> None:
    victim_process = _FakeProcess(exited=False)
    gateway_process = _FakeProcess(exited=False)
    runner = _FakeRunner([victim_process, gateway_process])
    monkeypatch.setattr(arp.time, 'sleep', lambda seconds: None)

    device = DeviceConfig(name='dev1', ip='192.168.1.50')
    attack = ArpSpoofAttackConfig(
        name='arp_spoof',
        label='ARP_Spoof',
        interface='eth0',
        gateway_ip='192.168.1.1',
        duration_seconds=30,
        bidirectional=True,
    )
    executor = arp.ArpSpoofExecutor(runner=runner, attack=attack)

    detail = executor.execute(device=device)

    assert runner.popen_calls == [
        ['arpspoof', '-i', 'eth0', '-t', '192.168.1.50', '192.168.1.1'],
        ['arpspoof', '-i', 'eth0', '-t', '192.168.1.1', '192.168.1.50'],
    ]
    assert victim_process.terminate_called is True
    assert gateway_process.terminate_called is True
    assert detail == 'duration_seconds=30, bidirectional=true'


def test_arp_spoof_executor_bidirectional_raises_if_gateway_direction_exits_immediately(monkeypatch) -> None:
    victim_process = _FakeProcess(exited=False)
    gateway_process = _FakeProcess(exited=True, returncode=1, stderr='arpspoof: eth9: No such device exists')
    runner = _FakeRunner([victim_process, gateway_process])
    monkeypatch.setattr(arp.time, 'sleep', lambda seconds: None)

    device = DeviceConfig(name='dev1', ip='192.168.1.50')
    attack = ArpSpoofAttackConfig(
        name='arp_spoof',
        label='ARP_Spoof',
        interface='eth9',
        gateway_ip='192.168.1.1',
        bidirectional=True,
    )
    executor = arp.ArpSpoofExecutor(runner=runner, attack=attack)

    with pytest.raises(AttackExecutionError, match='No such device exists'):
        executor.execute(device=device)

    assert victim_process.terminate_called is True
