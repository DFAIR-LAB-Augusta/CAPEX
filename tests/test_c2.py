from __future__ import annotations

from capex.attacks import c2
from capex.models import C2BeaconAttackConfig, DeviceConfig


class _FakeTcpSocket:
    def __init__(self) -> None:
        self.sent: bytes = b''

    def settimeout(self, timeout: float) -> None:
        pass

    def sendall(self, data: bytes) -> None:
        self.sent = data

    def recv(self, bufsize: int) -> bytes:
        return b'HTTP/1.1 200 OK\r\n'

    def __enter__(self) -> _FakeTcpSocket:
        return self

    def __exit__(self, *exc_info: object) -> None:
        pass


def test_c2_beacon_executor_sends_beacon_request(monkeypatch) -> None:
    fake_socket = _FakeTcpSocket()
    addresses: list[tuple[str, int]] = []

    def fake_create_connection(address, timeout):
        addresses.append(address)
        return fake_socket

    sleep_calls: list[float] = []
    monkeypatch.setattr(c2.socket, 'create_connection', fake_create_connection)
    monkeypatch.setattr(c2.random, 'uniform', lambda a, b: 1.5)
    monkeypatch.setattr(c2.time, 'sleep', lambda seconds: sleep_calls.append(seconds))

    device = DeviceConfig(name='dev1', ip='192.168.1.1')
    attack = C2BeaconAttackConfig(name='c2_beacon', label='C2_Beacon', port=8080, path='/check-in', jitter_seconds=5)
    executor = c2.C2BeaconExecutor(attack=attack)

    detail = executor.execute(device=device)

    assert detail == 'beacon=sent'
    assert addresses == [('192.168.1.1', 8080)]
    assert sleep_calls == [1.5]
    assert (
        fake_socket.sent
        == b'GET /check-in HTTP/1.1\r\nHost: 192.168.1.1\r\nUser-Agent: capex-c2-sim/1.0\r\nConnection: close\r\n\r\n'
    )


def test_c2_beacon_executor_skips_sleep_when_jitter_is_zero(monkeypatch) -> None:
    fake_socket = _FakeTcpSocket()
    sleep_calls: list[float] = []
    monkeypatch.setattr(c2.socket, 'create_connection', lambda address, timeout: fake_socket)
    monkeypatch.setattr(c2.time, 'sleep', lambda seconds: sleep_calls.append(seconds))

    device = DeviceConfig(name='dev1', ip='192.168.1.1')
    attack = C2BeaconAttackConfig(name='c2_beacon', label='C2_Beacon', jitter_seconds=0)
    executor = c2.C2BeaconExecutor(attack=attack)

    executor.execute(device=device)

    assert sleep_calls == []


def test_c2_beacon_executor_ignores_recv_timeout_after_send(monkeypatch) -> None:
    class _TimingOutSocket(_FakeTcpSocket):
        def recv(self, bufsize: int) -> bytes:
            raise TimeoutError

    fake_socket = _TimingOutSocket()
    monkeypatch.setattr(c2.socket, 'create_connection', lambda address, timeout: fake_socket)
    monkeypatch.setattr(c2.time, 'sleep', lambda seconds: None)

    device = DeviceConfig(name='dev1', ip='192.168.1.1')
    attack = C2BeaconAttackConfig(name='c2_beacon', label='C2_Beacon', jitter_seconds=0)
    executor = c2.C2BeaconExecutor(attack=attack)

    detail = executor.execute(device=device)

    assert detail == 'beacon=sent'


def test_c2_beacon_executor_returns_unreachable_on_connection_failure(monkeypatch) -> None:
    def refuse(address, timeout):
        raise ConnectionRefusedError

    monkeypatch.setattr(c2.socket, 'create_connection', refuse)
    monkeypatch.setattr(c2.time, 'sleep', lambda seconds: None)

    device = DeviceConfig(name='dev1', ip='192.168.1.1')
    attack = C2BeaconAttackConfig(name='c2_beacon', label='C2_Beacon', jitter_seconds=0)
    executor = c2.C2BeaconExecutor(attack=attack)

    detail = executor.execute(device=device)

    assert detail == 'beacon=<unreachable>'
