from __future__ import annotations

import itertools
import tempfile

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from capex.models import DeviceConfig, HydraBruteForceAttackConfig
    from capex.runner import CommandRunner


class HydraBruteForceExecutor:
    """Runs real hydra against a device using a combo file capped at max_attempts.

    The credential-pair list is truncated in code before hydra ever runs, so
    the attempt cap holds regardless of how hydra's own flags are configured
    - this bounds lockout/bricking risk against real lab hardware.
    """

    def __init__(self, *, runner: CommandRunner, attack: HydraBruteForceAttackConfig) -> None:
        self._runner = runner
        self._attack = attack

    def execute(self, *, device: DeviceConfig) -> str | None:
        pairs = list(
            itertools.islice(
                itertools.product(self._attack.username_list, self._attack.password_list),
                self._attack.max_attempts,
            )
        )
        combo_text = ''.join(f'{user}:{password}\n' for user, password in pairs)

        with tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False) as handle:
            handle.write(combo_text)
            combo_path = Path(handle.name)

        try:
            self._runner.run(
                [
                    self._attack.hydra_binary,
                    '-C',
                    str(combo_path),
                    '-t',
                    str(self._attack.tasks),
                    str(device.ip),
                    self._attack.service,
                    '-s',
                    str(self._attack.port),
                ],
                check=False,
            )
        finally:
            combo_path.unlink(missing_ok=True)

        return f'attempts={len(pairs)}'
