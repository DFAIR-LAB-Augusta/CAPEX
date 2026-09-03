from __future__ import annotations

from capex.attacks import application_layer
from capex.models import DeviceConfig, HttpFuzzAttackConfig


class _FakeTcpSocket:
    def __init__(self, *, recv_data: bytes = b'HTTP/1.1 404 Not Found\r\n') -> None:
        self._recv_data = recv_data
        self.sent: bytes = b''

    def settimeout(self, timeout: float) -> None:
        pass

    def sendall(self, data: bytes) -> None:
        self.sent = data

    def recv(self, bufsize: int) -> bytes:
        return self._recv_data

    def __enter__(self) -> _FakeTcpSocket:
        return self

    def __exit__(self, *exc_info: object) -> None:
        pass


class _FakeSocketFactory:
    def __init__(self, items: list) -> None:
        self._items = list(items)
        self.addresses: list[tuple[str, int]] = []

    def __call__(self, address, timeout):
        self.addresses.append(address)
        item = self._items.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def test_http_fuzz_executor_sends_all_configured_paths(monkeypatch) -> None:
    sockets = [_FakeTcpSocket(), _FakeTcpSocket()]
    factory = _FakeSocketFactory(sockets)
    monkeypatch.setattr(application_layer.socket, 'create_connection', factory)

    device = DeviceConfig(name='dev1', ip='192.168.1.1')
    attack = HttpFuzzAttackConfig(
        name='http_fuzz',
        label='HTTP_Fuzz',
        port=80,
        paths=['/../../../../etc/passwd', "/'; DROP TABLE users;--"],
    )
    executor = application_layer.HttpFuzzExecutor(attack=attack)

    detail = executor.execute(device=device)

    assert detail == 'requests=2, responses=2'
    assert factory.addresses == [('192.168.1.1', 80), ('192.168.1.1', 80)]
    assert sockets[0].sent == b'GET /../../../../etc/passwd HTTP/1.1\r\nHost: 192.168.1.1\r\nConnection: close\r\n\r\n'
    assert sockets[1].sent == b"GET /'; DROP TABLE users;-- HTTP/1.1\r\nHost: 192.168.1.1\r\nConnection: close\r\n\r\n"


def test_http_fuzz_executor_counts_recv_timeout_as_no_response(monkeypatch) -> None:
    class _TimingOutSocket(_FakeTcpSocket):
        def recv(self, bufsize: int) -> bytes:
            raise TimeoutError

    factory = _FakeSocketFactory([_TimingOutSocket()])
    monkeypatch.setattr(application_layer.socket, 'create_connection', factory)

    device = DeviceConfig(name='dev1', ip='192.168.1.1')
    attack = HttpFuzzAttackConfig(
        name='http_fuzz',
        label='HTTP_Fuzz',
        port=80,
        paths=['/slow'],
    )
    executor = application_layer.HttpFuzzExecutor(attack=attack)

    detail = executor.execute(device=device)

    assert detail == 'requests=1, responses=0'


def test_http_fuzz_executor_counts_unreachable_path_as_no_response(monkeypatch) -> None:
    factory = _FakeSocketFactory([ConnectionRefusedError(), _FakeTcpSocket()])
    monkeypatch.setattr(application_layer.socket, 'create_connection', factory)

    device = DeviceConfig(name='dev1', ip='192.168.1.1')
    attack = HttpFuzzAttackConfig(
        name='http_fuzz',
        label='HTTP_Fuzz',
        port=80,
        paths=['/nope', '/ok'],
    )
    executor = application_layer.HttpFuzzExecutor(attack=attack)

    detail = executor.execute(device=device)

    assert detail == 'requests=2, responses=1'
