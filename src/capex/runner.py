from __future__ import annotations

import logging
import subprocess

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

LOGGER = logging.getLogger(__name__)


@dataclass(slots=True, frozen=True)
class CompletedCommand:
    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


class CommandRunner:
    def run(
        self,
        args: Sequence[str],
        *,
        check: bool = True,
        cwd: Path | None = None,
    ) -> CompletedCommand:
        proc = subprocess.run(
            list(args),
            check=False,
            capture_output=True,
            text=True,
            cwd=cwd,
        )

        result = CompletedCommand(
            args=tuple(args),
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
        )

        if check and proc.returncode != 0:
            LOGGER.error('Command failed: %s', args)
            msg = f'Command failed with exit code {proc.returncode}: {args!r}'
            raise RuntimeError(msg)

        return result

    def popen(
        self,
        args: Sequence[str],
        *,
        cwd: Path | None = None,
    ) -> subprocess.Popen[str]:
        return subprocess.Popen(
            list(args),
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
