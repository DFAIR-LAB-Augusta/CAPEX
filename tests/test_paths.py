from __future__ import annotations

from pathlib import Path

from capex.models import CaptureConfig, DeviceConfig
from capex.paths import build_log_path, build_pcap_path, ensure_capture_directories, ensure_directory


def test_ensure_directory_creates_nested_path(tmp_path) -> None:
    target = tmp_path / 'a' / 'b' / 'c'

    ensure_directory(target)

    assert target.is_dir()


def test_ensure_directory_is_idempotent(tmp_path) -> None:
    target = tmp_path / 'a'
    target.mkdir()

    ensure_directory(target)

    assert target.is_dir()


def test_ensure_capture_directories_creates_output_and_log_dirs(tmp_path) -> None:
    config = CaptureConfig(output_dir=tmp_path / 'raw', log_dir=tmp_path / 'logs')

    ensure_capture_directories(config)

    assert config.output_dir.is_dir()
    assert config.log_dir.is_dir()


def test_build_pcap_path() -> None:
    config = CaptureConfig(output_dir=Path('data/raw'), log_dir=Path('data/logs'))
    device = DeviceConfig(name='dev1', ip='192.168.1.1')

    assert build_pcap_path(config=config, device=device) == Path('data/raw/dev1_flow.pcap')


def test_build_log_path() -> None:
    config = CaptureConfig(output_dir=Path('data/raw'), log_dir=Path('data/logs'))
    device = DeviceConfig(name='dev1', ip='192.168.1.1')

    assert build_log_path(config=config, device=device) == Path('data/logs/dev1_CE.txt')
