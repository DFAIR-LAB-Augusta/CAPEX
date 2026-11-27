from __future__ import annotations

import csv
import logging
import time

from typing import TYPE_CHECKING

from capex.attacks.registry import AttackRegistry
from capex.capture import TcpdumpCapture
from capex.paths import build_ground_truth_path, build_log_path, build_pcap_path, new_session_id
from capex.scheduler import build_schedule

if TYPE_CHECKING:
    from pathlib import Path

    from capex.models import AttackConfig, CaptureConfig, DeviceConfig
    from capex.runner import CommandRunner

LOGGER = logging.getLogger(__name__)

GROUND_TRUTH_HEADER = ('session_id', 'device', 'target_ip', 'label', 'attempt', 'start_unix', 'end_unix')


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
        session_id = new_session_id()
        LOGGER.info('Starting capture session %s for device %s', session_id, device.name)
        pcap_path = build_pcap_path(config=self._config, device=device, session_id=session_id)
        log_path = build_log_path(config=self._config, device=device, session_id=session_id)

        ground_truth_path = build_ground_truth_path(config=self._config, device=device, session_id=session_id)

        capture = TcpdumpCapture(
            runner=self._runner,
            binary=self._config.tcpdump_binary,
        )

        capture.start(pcap_path)
        started_at = time.time()

        try:
            self._run_attacks(
                device=device,
                attacks=attacks,
                log_path=log_path,
                ground_truth_path=ground_truth_path,
                session_id=session_id,
            )
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
        ground_truth_path: Path,
        session_id: str,
    ) -> None:
        allowed = self._config.duration_seconds - self._config.safe_period_seconds

        enabled_attacks = [attack for attack in attacks if attack.enabled]
        if not enabled_attacks:
            LOGGER.warning('No enabled attacks for device %s', device.name)
            return

        schedule = build_schedule(
            repeats_per_attack=[attack.repeats for attack in enabled_attacks],
            allowed_duration_seconds=allowed,
        )

        started_at = time.time()

        with (
            log_path.open('x', encoding='utf-8') as handle,
            ground_truth_path.open('x', encoding='utf-8', newline='') as csv_handle,
        ):
            writer = csv.writer(csv_handle)
            writer.writerow(GROUND_TRUTH_HEADER)
            csv_handle.flush()

            for item in schedule:
                attack = enabled_attacks[item.attack_index]

                target_time = started_at + item.offset_seconds
                sleep_for = target_time - time.time()
                if sleep_for > 0:
                    time.sleep(sleep_for)

                executor = self._registry.resolve(attack)
                start = time.time()
                try:
                    detail = executor.execute(device=device)
                finally:
                    end = time.time()
                    writer.writerow(
                        [session_id, device.name, device.ip, attack.label, item.repeat_index + 1, start, end],
                    )
                    csv_handle.flush()

                line = (
                    'Attack: '
                    f'{attack.label}, '
                    f'Attempt: {item.repeat_index + 1}, '
                    f'Unix Time: {start}, '
                    f'Time Since Start: {start - started_at}, '
                    f'End Unix Time: {end}, '
                    f'Target IP: {device.ip}, '
                    f'Session: {session_id}'
                )
                if detail:
                    line += f', {detail}'
                handle.write(line + '\n')
                handle.flush()
