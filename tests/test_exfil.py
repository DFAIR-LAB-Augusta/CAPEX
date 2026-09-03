from __future__ import annotations

from capex.attacks import exfil
from capex.models import DeviceConfig, ExfilSimAttackConfig


class _FakeTcpSocket:
    def __init__(self, *, fail_after_chunks: int | None = None) -> None:
        self.sent_chunks: list[bytes] = []
        self._fail_after_chunks = fail_after_chunks

    def settimeout(self, timeout: float) -> None:
        pass

    def sendall(self, data: bytes) -> None:
        if self._fail_after_chunks is not None and len(self.sent_chunks) >= self._fail_after_chunks:
            raise ConnectionResetError
        self.sent_chunks.append(data)

    def recv(self, bufsize: int) -> bytes:
        return b'HTTP/1.1 200 OK\r\n'

    def __enter__(self) -> _FakeTcpSocket:
        return self

    def __exit__(self, *exc_info: object) -> None:
        pass


def test_exfil_executor_sends_header_then_chunks_totaling_payload_size(monkeypatch) -> None:
    fake_socket = _FakeTcpSocket()
    monkeypatch.setattr(exfil.socket, 'create_connection', lambda address, timeout: fake_socket)

    device = DeviceConfig(name='dev1', ip='192.168.1.1')
    attack = ExfilSimAttackConfig(
        name='exfil_sim',
        label='Exfil_Sim',
        port=8080,
        path='/upload',
        payload_size_bytes=150_000,
        chunk_size_bytes=65_536,
    )
    executor = exfil.ExfilSimExecutor(attack=attack)

    detail = executor.execute(device=device)

    assert detail == 'bytes_sent=150000'
    header = fake_socket.sent_chunks[0]
    assert header == (
        b'POST /upload HTTP/1.1\r\n'
        b'Host: 192.168.1.1\r\n'
        b'Content-Type: application/octet-stream\r\n'
        b'Content-Length: 150000\r\n'
        b'Connection: close\r\n\r\n'
    )
    body_chunks = fake_socket.sent_chunks[1:]
    assert [len(chunk) for chunk in body_chunks] == [65536, 65536, 18928]
    assert sum(len(chunk) for chunk in body_chunks) == 150_000


def test_exfil_executor_ignores_recv_timeout_after_full_send(monkeypatch) -> None:
    class _TimingOutSocket(_FakeTcpSocket):
        def recv(self, bufsize: int) -> bytes:
            raise TimeoutError

    fake_socket = _TimingOutSocket()
    monkeypatch.setattr(exfil.socket, 'create_connection', lambda address, timeout: fake_socket)

    device = DeviceConfig(name='dev1', ip='192.168.1.1')
    attack = ExfilSimAttackConfig(name='exfil_sim', label='Exfil_Sim', payload_size_bytes=1000)
    executor = exfil.ExfilSimExecutor(attack=attack)

    detail = executor.execute(device=device)

    assert detail == 'bytes_sent=1000'


def test_exfil_executor_returns_zero_on_connection_failure(monkeypatch) -> None:
    def refuse(address, timeout):
        raise ConnectionRefusedError

    monkeypatch.setattr(exfil.socket, 'create_connection', refuse)

    device = DeviceConfig(name='dev1', ip='192.168.1.1')
    attack = ExfilSimAttackConfig(name='exfil_sim', label='Exfil_Sim', port=80, payload_size_bytes=1000)
    executor = exfil.ExfilSimExecutor(attack=attack)

    detail = executor.execute(device=device)

    assert detail == 'bytes_sent=0'


def test_exfil_executor_reports_partial_bytes_sent_on_mid_stream_failure(monkeypatch) -> None:
    fake_socket = _FakeTcpSocket(fail_after_chunks=2)
    monkeypatch.setattr(exfil.socket, 'create_connection', lambda address, timeout: fake_socket)

    device = DeviceConfig(name='dev1', ip='192.168.1.1')
    attack = ExfilSimAttackConfig(
        name='exfil_sim',
        label='Exfil_Sim',
        port=80,
        payload_size_bytes=150_000,
        chunk_size_bytes=65_536,
    )
    executor = exfil.ExfilSimExecutor(attack=attack)

    detail = executor.execute(device=device)

    assert detail == 'bytes_sent=65536'
