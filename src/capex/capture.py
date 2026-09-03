from __future__ import annotations

import subprocess
import time

from dataclasses import dataclass
from typing import TYPE_CHECKING

from capex.exceptions import CaptureError

if TYPE_CHECKING:
    from pathlib import Path

    from capex.runner import CommandRunner

START_CHECK_DELAY_SECONDS = 0.3
STOP_TIMEOUT_SECONDS = 15
KILL_TIMEOUT_SECONDS = 5


@dataclass(slots=True)
class TcpdumpCapture:
    runner: CommandRunner
    binary: str = 'tcpdump'
    process: subprocess.Popen[str] | None = None
    start_check_delay_seconds: float = START_CHECK_DELAY_SECONDS

    def start(self, output_path: Path) -> None:
        if self.process is not None:
            raise CaptureError('tcpdump capture already running')

        process = self.runner.popen([self.binary, '-w', str(output_path)])

        if self.start_check_delay_seconds > 0:
            time.sleep(self.start_check_delay_seconds)

        if process.poll() is not None:
            _, stderr = process.communicate()
            msg = (
                f'{self.binary} exited immediately with code {process.returncode} '
                f'while starting capture to {output_path}: {stderr.strip()}'
            )
            raise CaptureError(msg)

        self.process = process

    def stop(self) -> None:
        if self.process is None:
            return

        process = self.process
        self.process = None

        process.terminate()
        try:
            process.wait(timeout=STOP_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=KILL_TIMEOUT_SECONDS)
