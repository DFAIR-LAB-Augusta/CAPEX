from __future__ import annotations

from capex.attacks import c2_dns
from capex.models import C2DnsBeaconAttackConfig, DeviceConfig


class _FakeUdpSocket:
    def __init__(self, *, response: bytes | None = b'\x00' * 12) -> None:
        self._response = response
        self.sent: list[tuple[bytes, tuple[str, int]]] = []

    def settimeout(self, timeout: float) -> None:
        pass

    def sendto(self, data: bytes, address: tuple[str, int]) -> None:
        self.sent.append((data, address))

    def recvfrom(self, bufsize: int) -> tuple[bytes, tuple[str, int]]:
        if self._response is None:
            raise TimeoutError
        return self._response, ('192.168.1.1', 53)

    def __enter__(self) -> _FakeUdpSocket:
        return self

    def __exit__(self, *exc_info: object) -> None:
        pass


def test_build_dns_query_produces_valid_wire_format() -> None:
    message = c2_dns.build_dns_query(domain='update-check.example', query_id=0x1234)

    header = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
    qname = b'\x0cupdate-check\x07example\x00'
    question_tail = b'\x00\x01\x00\x01'

    assert message == header + qname + question_tail


def test_dns_beacon_executor_sends_query_and_reports_response(monkeypatch) -> None:
    fake_socket = _FakeUdpSocket(response=b'\x12\x34' + b'\x00' * 10)
    monkeypatch.setattr(c2_dns.socket, 'socket', lambda *args, **kwargs: fake_socket)
    monkeypatch.setattr(c2_dns.random, 'randint', lambda a, b: 0x1234)
    monkeypatch.setattr(c2_dns.random, 'uniform', lambda a, b: 0.0)
    monkeypatch.setattr(c2_dns.time, 'sleep', lambda seconds: None)

    device = DeviceConfig(name='dev1', ip='192.168.1.1')
    attack = C2DnsBeaconAttackConfig(name='c2_dns_beacon', label='C2_DNS_Beacon', domain='update-check.example')
    executor = c2_dns.DnsC2BeaconExecutor(attack=attack)

    detail = executor.execute(device=device)

    assert detail == 'beacon=sent, responded=True'
    sent_data, address = fake_socket.sent[0]
    assert address == ('192.168.1.1', 53)
    assert sent_data == c2_dns.build_dns_query(domain='update-check.example', query_id=0x1234)


def test_dns_beacon_executor_reports_no_response_on_timeout(monkeypatch) -> None:
    fake_socket = _FakeUdpSocket(response=None)
    monkeypatch.setattr(c2_dns.socket, 'socket', lambda *args, **kwargs: fake_socket)
    monkeypatch.setattr(c2_dns.random, 'randint', lambda a, b: 0x1234)
    monkeypatch.setattr(c2_dns.time, 'sleep', lambda seconds: None)

    device = DeviceConfig(name='dev1', ip='192.168.1.1')
    attack = C2DnsBeaconAttackConfig(name='c2_dns_beacon', label='C2_DNS_Beacon', jitter_seconds=0)
    executor = c2_dns.DnsC2BeaconExecutor(attack=attack)

    detail = executor.execute(device=device)

    assert detail == 'beacon=sent, responded=False'


def test_dns_beacon_executor_applies_jitter_before_sending(monkeypatch) -> None:
    fake_socket = _FakeUdpSocket()
    sleep_calls: list[float] = []
    monkeypatch.setattr(c2_dns.socket, 'socket', lambda *args, **kwargs: fake_socket)
    monkeypatch.setattr(c2_dns.random, 'randint', lambda a, b: 0x1234)
    monkeypatch.setattr(c2_dns.random, 'uniform', lambda a, b: 2.5)
    monkeypatch.setattr(c2_dns.time, 'sleep', lambda seconds: sleep_calls.append(seconds))

    device = DeviceConfig(name='dev1', ip='192.168.1.1')
    attack = C2DnsBeaconAttackConfig(name='c2_dns_beacon', label='C2_DNS_Beacon', jitter_seconds=5)
    executor = c2_dns.DnsC2BeaconExecutor(attack=attack)

    executor.execute(device=device)

    assert sleep_calls == [2.5]
