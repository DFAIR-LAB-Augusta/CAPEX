from __future__ import annotations

import subprocess

import pytest

from capex.capture import TcpdumpCapture
from capex.exceptions import CaptureError


class _FakeProcess:
    def __init__(self, *, exited: bool = False, returncode: int = 1, stderr: str = '') -> None:
        self._exited = exited
        self.returncode = returncode if exited else None
        self._stderr = stderr
        self.terminate_called = False
        self.kill_called = False
        self._wait_calls = 0
        self._timeout_on_first_wait = False

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
        if self._timeout_on_first_wait and self._wait_calls == 1:
            raise subprocess.TimeoutExpired(cmd='tcpdump', timeout=timeout or 0)
        self.returncode = self.returncode if self.returncode is not None else -15
        return self.returncode


class _FakeRunner:
    def __init__(self, process: _FakeProcess) -> None:
        self._process = process
        self.popen_args: list[str] | None = None

    def popen(self, args, *, cwd=None):
        self.popen_args = list(args)
        return self._process


def test_start_succeeds_when_process_stays_alive(tmp_path) -> None:
    process = _FakeProcess(exited=False)
    runner = _FakeRunner(process)
    capture = TcpdumpCapture(runner=runner, start_check_delay_seconds=0)

    capture.start(tmp_path / 'out.pcap')

    assert capture.process is process
    assert runner.popen_args[0] == 'tcpdump'


def test_start_raises_capture_error_when_already_running(tmp_path) -> None:
    process = _FakeProcess(exited=False)
    capture = TcpdumpCapture(runner=_FakeRunner(process), process=process)

    with pytest.raises(CaptureError, match='already running'):
        capture.start(tmp_path / 'out.pcap')


def test_start_raises_capture_error_when_process_exits_immediately(tmp_path) -> None:
    process = _FakeProcess(exited=True, returncode=1, stderr='tcpdump: eth9: No such device exists')
    runner = _FakeRunner(process)
    capture = TcpdumpCapture(runner=runner, start_check_delay_seconds=0)

    with pytest.raises(CaptureError, match='No such device exists'):
        capture.start(tmp_path / 'out.pcap')

    assert capture.process is None


def test_stop_terminates_running_process() -> None:
    process = _FakeProcess(exited=False)
    capture = TcpdumpCapture(runner=_FakeRunner(process), process=process)

    capture.stop()

    assert process.terminate_called is True
    assert process.kill_called is False
    assert capture.process is None


def test_stop_kills_process_that_does_not_terminate_in_time() -> None:
    process = _FakeProcess(exited=False)
    process._timeout_on_first_wait = True
    capture = TcpdumpCapture(runner=_FakeRunner(process), process=process)

    capture.stop()

    assert process.terminate_called is True
    assert process.kill_called is True
    assert capture.process is None


def test_stop_is_a_noop_when_no_process_is_running() -> None:
    process = _FakeProcess(exited=False)
    capture = TcpdumpCapture(runner=_FakeRunner(process))

    capture.stop()

    assert process.terminate_called is False
