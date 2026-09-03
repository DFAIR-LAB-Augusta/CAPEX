from __future__ import annotations

from capex.attacks import discovery
from capex.models import BannerGrabAttackConfig, DeviceConfig, SsdpDiscoveryAttackConfig


class _FakeUdpSocket:
    def __init__(self, responses: list[bytes]) -> None:
        self._responses = list(responses)
        self.sent: list[tuple[bytes, tuple[str, int]]] = []

    def settimeout(self, timeout: float) -> None:
        pass

    def sendto(self, data: bytes, address: tuple[str, int]) -> None:
        self.sent.append((data, address))

    def recvfrom(self, bufsize: int) -> tuple[bytes, tuple[str, int]]:
        if not self._responses:
            raise TimeoutError
        return self._responses.pop(0), ('192.168.1.1', 1900)

    def __enter__(self) -> _FakeUdpSocket:
        return self

    def __exit__(self, *exc_info: object) -> None:
        pass


def test_ssdp_discovery_executor_counts_responses(monkeypatch) -> None:
    fake_socket = _FakeUdpSocket(
        responses=[
            b'HTTP/1.1 200 OK\r\nSERVER: Linux/1.0 UPnP/1.0\r\n\r\n',
            b'HTTP/1.1 200 OK\r\nSERVER: Linux/1.0 UPnP/1.0\r\n\r\n',
        ]
    )
    monkeypatch.setattr(discovery.socket, 'socket', lambda *args, **kwargs: fake_socket)

    device = DeviceConfig(name='dev1', ip='192.168.1.1')
    attack = SsdpDiscoveryAttackConfig(name='ssdp_discovery', label='SSDP_Discovery')
    executor = discovery.SsdpDiscoveryExecutor(attack=attack)

    detail = executor.execute(device=device)

    assert detail == 'responses=2'
    assert fake_socket.sent[0][1] == ('192.168.1.1', 1900)


def test_ssdp_discovery_executor_returns_zero_on_no_response(monkeypatch) -> None:
    fake_socket = _FakeUdpSocket(responses=[])
    monkeypatch.setattr(discovery.socket, 'socket', lambda *args, **kwargs: fake_socket)

    device = DeviceConfig(name='dev1', ip='192.168.1.1')
    attack = SsdpDiscoveryAttackConfig(name='ssdp_discovery', label='SSDP_Discovery')
    executor = discovery.SsdpDiscoveryExecutor(attack=attack)

    detail = executor.execute(device=device)

    assert detail == 'responses=0'


class _FakeTcpSocket:
    def __init__(self, *, recv_data: bytes = b'', recv_error: Exception | None = None) -> None:
        self._recv_data = recv_data
        self._recv_error = recv_error
        self.sent: bytes = b''

    def settimeout(self, timeout: float) -> None:
        pass

    def sendall(self, data: bytes) -> None:
        self.sent = data

    def recv(self, bufsize: int) -> bytes:
        if self._recv_error is not None:
            raise self._recv_error
        return self._recv_data

    def __enter__(self) -> _FakeTcpSocket:
        return self

    def __exit__(self, *exc_info: object) -> None:
        pass


def test_banner_grab_executor_returns_banner_text(monkeypatch) -> None:
    fake_socket = _FakeTcpSocket(recv_data=b'220 ready\r\n')
    monkeypatch.setattr(discovery.socket, 'create_connection', lambda address, timeout: fake_socket)

    device = DeviceConfig(name='dev1', ip='192.168.1.1')
    attack = BannerGrabAttackConfig(name='banner_grab', label='Banner_Grab', port=23)
    executor = discovery.BannerGrabExecutor(attack=attack)

    detail = executor.execute(device=device)

    assert detail == "banner='220 ready'"


def test_banner_grab_executor_sends_configured_probe(monkeypatch) -> None:
    fake_socket = _FakeTcpSocket(recv_data=b'HTTP/1.1 200 OK\r\n')
    monkeypatch.setattr(discovery.socket, 'create_connection', lambda address, timeout: fake_socket)

    device = DeviceConfig(name='dev1', ip='192.168.1.1')
    attack = BannerGrabAttackConfig(
        name='banner_grab_http',
        label='Banner_Grab_HTTP',
        port=80,
        probe='HEAD / HTTP/1.0\r\nHost: {target_ip}\r\n\r\n',
    )
    executor = discovery.BannerGrabExecutor(attack=attack)

    executor.execute(device=device)

    assert fake_socket.sent == b'HEAD / HTTP/1.0\r\nHost: 192.168.1.1\r\n\r\n'


def test_banner_grab_executor_handles_connection_refused(monkeypatch) -> None:
    def refuse(address: tuple[str, int], timeout: float) -> None:
        raise ConnectionRefusedError

    monkeypatch.setattr(discovery.socket, 'create_connection', refuse)

    device = DeviceConfig(name='dev1', ip='192.168.1.1')
    attack = BannerGrabAttackConfig(name='banner_grab', label='Banner_Grab', port=23)
    executor = discovery.BannerGrabExecutor(attack=attack)

    detail = executor.execute(device=device)

    assert detail == 'banner=<connection failed>'


def test_banner_grab_executor_handles_no_response(monkeypatch) -> None:
    fake_socket = _FakeTcpSocket(recv_error=TimeoutError)
    monkeypatch.setattr(discovery.socket, 'create_connection', lambda address, timeout: fake_socket)

    device = DeviceConfig(name='dev1', ip='192.168.1.1')
    attack = BannerGrabAttackConfig(name='banner_grab', label='Banner_Grab', port=23)
    executor = discovery.BannerGrabExecutor(attack=attack)

    detail = executor.execute(device=device)

    assert detail == 'banner=<no response>'
