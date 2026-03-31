from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import subprocess

    from pathlib import Path

    from capex.runner import CommandRunner


@dataclass(slots=True)
class TcpdumpCapture:
    runner: CommandRunner
    binary: str = 'tcpdump'
    process: subprocess.Popen[str] | None = None

    def start(self, output_path: Path) -> None:
        if self.process is not None:
            raise RuntimeError('tcpdump capture already running')

        self.process = self.runner.popen([self.binary, '-w', str(output_path)])

    def stop(self) -> None:
        if self.process is None:
            return

        self.process.terminate()
        self.process.wait(timeout=15)
        self.process = None
