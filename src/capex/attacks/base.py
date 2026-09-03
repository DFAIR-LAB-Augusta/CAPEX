from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from capex.models import DeviceConfig


class BoundAttackExecutor(Protocol):
    def execute(self, *, device: DeviceConfig) -> str | None:
        """Run the attack against ``device``.

        Returns an optional short, single-line detail string (e.g. a
        request count) to be appended to the capture session's attack
        log entry for this invocation. The capture session owns all
        writes to the attack log; executors must not write to it
        themselves.
        """
        ...
