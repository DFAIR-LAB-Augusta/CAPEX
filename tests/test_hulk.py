from __future__ import annotations

import threading

from capex.attacks import hulk
from capex.models import DeviceConfig, HulkAttackConfig


def test_hulk_attack_executor_floods_and_returns_request_count(monkeypatch) -> None:
    call_count = 0
    lock = threading.Lock()

    def fake_urlopen(request, timeout=None):
        nonlocal call_count
        with lock:
            call_count += 1
        return None

    monkeypatch.setattr(hulk.urllib.request, 'urlopen', fake_urlopen)

    device = DeviceConfig(name='dev1', ip='192.168.1.1')
    attack = HulkAttackConfig(
        name='hulk_http_flood',
        label='HULK_HTTP_Flood',
        thread_count=3,
        duration_seconds=1,
    )
    executor = hulk.HulkAttackExecutor(attack=attack)

    detail = executor.execute(device=device)

    assert detail is not None
    assert detail.startswith('requests=')
    assert call_count > 0
    assert detail == f'requests={call_count}'


def test_hulk_attack_executor_backs_off_on_unreachable_target(monkeypatch) -> None:
    def failing_urlopen(request, timeout=None):
        raise hulk.urllib.error.URLError('connection refused')

    monkeypatch.setattr(hulk.urllib.request, 'urlopen', failing_urlopen)

    device = DeviceConfig(name='dev1', ip='192.168.1.1')
    attack = HulkAttackConfig(
        name='hulk_http_flood',
        label='HULK_HTTP_Flood',
        thread_count=2,
        duration_seconds=1,
    )
    executor = hulk.HulkAttackExecutor(attack=attack)

    detail = executor.execute(device=device)

    assert detail == 'requests=0'
