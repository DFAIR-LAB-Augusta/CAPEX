from __future__ import annotations

from pathlib import Path

from capex.cli import build_parser


def test_build_parser_returns_expected_defaults() -> None:
    parser = build_parser()
    args = parser.parse_args([])

    assert args.devices == Path('configs/devices.yaml')
    assert args.attacks == Path('configs/attacks.yaml')
    assert args.duration_seconds == 8 * 60 * 60
    assert args.safe_period_seconds == 15 * 60
    assert args.output_dir == Path('data/raw')
    assert args.log_dir == Path('data/logs')
    assert args.device == []
    assert args.dry_run is False
    assert args.verbose is False


def test_parser_accepts_custom_values() -> None:
    parser = build_parser()
    args = parser.parse_args([
        '--devices',
        'my_devices.yaml',
        '--attacks',
        'my_attacks.yaml',
        '--duration-seconds',
        '120',
        '--safe-period-seconds',
        '15',
        '--output-dir',
        'out/raw',
        '--log-dir',
        'out/logs',
        '--device',
        'nestCam',
        '--device',
        'phillipsHub',
        '--dry-run',
        '--verbose',
    ])

    assert args.devices == Path('my_devices.yaml')
    assert args.attacks == Path('my_attacks.yaml')
    assert args.duration_seconds == 120
    assert args.safe_period_seconds == 15
    assert args.output_dir == Path('out/raw')
    assert args.log_dir == Path('out/logs')
    assert args.device == ['nestCam', 'phillipsHub']
    assert args.dry_run is True
    assert args.verbose is True
