from __future__ import annotations

from capex.cli import build_parser


def test_cli_parser_builds() -> None:
    parser = build_parser()
    args = parser.parse_args(['--dry-run'])
    assert args.dry_run is True
