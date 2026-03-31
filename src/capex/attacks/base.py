from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from pathlib import Path

    from capex.models import DeviceConfig


class BoundAttackExecutor(Protocol):
    def execute(
        self,
        *,
        device: DeviceConfig,
        log_path: Path,
    ) -> None: ...
