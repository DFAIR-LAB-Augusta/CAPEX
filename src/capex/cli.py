from __future__ import annotations

import argparse

from pathlib import Path

from capex.config import load_attacks, load_devices
from capex.logging_utils import configure_logging
from capex.models import CaptureConfig
from capex.paths import ensure_capture_directories
from capex.runner import CommandRunner
from capex.services.capture_session import CaptureSession
from capex.validation import (
    validate_attacks,
    validate_capture_config,
    validate_config_paths,
    validate_devices,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='capex',
        description='Config-driven network capture orchestrator',
    )
    parser.add_argument(
        '--devices',
        type=Path,
        default=Path('configs/devices.yaml'),
        help='Path to devices YAML file',
    )
    parser.add_argument(
        '--attacks',
        type=Path,
        default=Path('configs/attacks.yaml'),
        help='Path to attacks YAML file',
    )
    parser.add_argument(
        '--duration-seconds',
        type=int,
        default=8 * 60 * 60,
    )
    parser.add_argument(
        '--safe-period-seconds',
        type=int,
        default=15 * 60,
    )
    parser.add_argument(
        '--output-dir',
        type=Path,
        default=Path('data/raw'),
    )
    parser.add_argument(
        '--log-dir',
        type=Path,
        default=Path('data/logs'),
    )
    parser.add_argument(
        '--device',
        action='append',
        default=[],
        help='Only run named device(s)',
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Validate config and print plan without running commands',
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    configure_logging(verbose=args.verbose)

    validate_config_paths(
        devices_path=args.devices,
        attacks_path=args.attacks,
    )

    config = CaptureConfig(
        duration_seconds=args.duration_seconds,
        safe_period_seconds=args.safe_period_seconds,
        output_dir=args.output_dir,
        log_dir=args.log_dir,
    )

    validate_capture_config(config)

    devices = load_devices(args.devices).devices
    attacks = load_attacks(args.attacks).attacks

    validate_devices(devices)
    validate_attacks(attacks)

    ensure_capture_directories(config)

    if args.device:
        allowed = set(args.device)
        devices = [device for device in devices if device.name in allowed]

    if args.dry_run:
        for device in devices:
            print(f'device={device.name} ip={device.ip}')
        for attack in attacks:
            print(f'attack={attack.name} repeats={attack.repeats}')
        return 0

    runner = CommandRunner()
    session = CaptureSession(runner=runner, config=config)

    for device in devices:
        if not device.enabled:
            continue
        session.run(device=device, attacks=attacks)

    return 0
