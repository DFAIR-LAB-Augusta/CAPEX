from __future__ import annotations

import logging
import time

from typing import TYPE_CHECKING

from capex.attacks.registry import AttackRegistry
from capex.capture import TcpdumpCapture
from capex.paths import build_log_path, build_pcap_path
from capex.scheduler import build_schedule

if TYPE_CHECKING:
    from pathlib import Path

    from capex.models import AttackConfig, CaptureConfig, DeviceConfig
    from capex.runner import CommandRunner

LOGGER = logging.getLogger(__name__)


class CaptureSession:
    def __init__(
        self,
        *,
        runner: CommandRunner,
        config: CaptureConfig,
    ) -> None:
        self._runner = runner
        self._config = config
        self._registry = AttackRegistry(runner=runner)

    def run(
        self,
        *,
        device: DeviceConfig,
        attacks: list[AttackConfig],
    ) -> None:
        pcap_path = build_pcap_path(config=self._config, device=device)
        log_path = build_log_path(config=self._config, device=device)

        capture = TcpdumpCapture(
            runner=self._runner,
            binary=self._config.tcpdump_binary,
        )

        capture.start(pcap_path)
        started_at = time.time()

        try:
            self._run_attacks(device=device, attacks=attacks, log_path=log_path)
            remaining = (started_at + self._config.duration_seconds) - time.time()
            if remaining > 0:
                time.sleep(remaining)
        finally:
            capture.stop()

    def _run_attacks(
        self,
        *,
        device: DeviceConfig,
        attacks: list[AttackConfig],
        log_path: Path,
    ) -> None:
        allowed = self._config.duration_seconds - self._config.safe_period_seconds

        enabled_attacks = [attack for attack in attacks if attack.enabled]
        if not enabled_attacks:
            LOGGER.warning('No enabled attacks for device %s', device.name)
            return

        repeats = max(attack.repeats for attack in enabled_attacks)
        schedule = build_schedule(
            attack_count=len(enabled_attacks),
            repeats_per_attack=repeats,
            allowed_duration_seconds=allowed,
        )

        started_at = time.time()

        with log_path.open('w', encoding='utf-8') as handle:
            for item in schedule:
                attack = enabled_attacks[item.attack_index]
                if item.repeat_index >= attack.repeats:
                    continue

                target_time = started_at + item.offset_seconds
                sleep_for = target_time - time.time()
                if sleep_for > 0:
                    time.sleep(sleep_for)

                executor = self._registry.resolve(attack)
                now = time.time()
                executor.execute(
                    device=device,
                    log_path=log_path,
                )

                handle.write(
                    'Attack: '
                    f'{attack.label}, '
                    f'Attempt: {item.repeat_index + 1}, '
                    f'Unix Time: {now}, '
                    f'Time Since Start: {now - started_at}\n'
                )
                handle.flush()
