from __future__ import annotations

from capex.attacks import impact
from capex.models import ConfigTamperAttackConfig, DeviceConfig


class _FakeTcpSocket:
    def __init__(self, *, recv_data: bytes = b'HTTP/1.1 403 Forbidden\r\n') -> None:
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


def test_config_tamper_attack_defaults_to_disabled() -> None:
    attack = ConfigTamperAttackConfig(
        name='config_tamper',
        label='Config_Tamper',
        path='/setup.cgi',
        body='ssid=pwned',
    )
    assert attack.enabled is False


def test_config_tamper_executor_sends_request_and_returns_status(monkeypatch) -> None:
    fake_socket = _FakeTcpSocket(recv_data=b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n')
    monkeypatch.setattr(impact.socket, 'create_connection', lambda address, timeout: fake_socket)

    device = DeviceConfig(name='dev1', ip='192.168.1.1')
    attack = ConfigTamperAttackConfig(
        name='config_tamper',
        label='Config_Tamper',
        port=80,
        path='/setup.cgi',
        body='ssid=pwned&password=pwned',
    )
    executor = impact.ConfigTamperExecutor(attack=attack)

    detail = executor.execute(device=device)

    assert detail == "response='HTTP/1.1 403 Forbidden'"
    assert fake_socket.sent == (
        b'POST /setup.cgi HTTP/1.1\r\n'
        b'Host: 192.168.1.1\r\n'
        b'Content-Type: application/x-www-form-urlencoded\r\n'
        b'Content-Length: 25\r\n'
        b'Connection: close\r\n\r\n'
        b'ssid=pwned&password=pwned'
    )


def test_config_tamper_executor_returns_unreachable_on_connection_failure(monkeypatch) -> None:
    def refuse(address, timeout):
        raise ConnectionRefusedError

    monkeypatch.setattr(impact.socket, 'create_connection', refuse)

    device = DeviceConfig(name='dev1', ip='192.168.1.1')
    attack = ConfigTamperAttackConfig(name='config_tamper', label='Config_Tamper', path='/setup.cgi', body='x=1')
    executor = impact.ConfigTamperExecutor(attack=attack)

    detail = executor.execute(device=device)

    assert detail == 'response=<unreachable>'


def test_config_tamper_executor_returns_no_response_on_timeout(monkeypatch) -> None:
    class _TimingOutSocket(_FakeTcpSocket):
        def recv(self, bufsize: int) -> bytes:
            raise TimeoutError

    fake_socket = _TimingOutSocket()
    monkeypatch.setattr(impact.socket, 'create_connection', lambda address, timeout: fake_socket)

    device = DeviceConfig(name='dev1', ip='192.168.1.1')
    attack = ConfigTamperAttackConfig(name='config_tamper', label='Config_Tamper', path='/setup.cgi', body='x=1')
    executor = impact.ConfigTamperExecutor(attack=attack)

    detail = executor.execute(device=device)

    assert detail == 'response=<no response>'
