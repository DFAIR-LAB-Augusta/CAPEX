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


def test_config_tamper_executor_sends_custom_content_type_and_soap_action(monkeypatch) -> None:
    fake_socket = _FakeTcpSocket(recv_data=b'HTTP/1.1 200 OK\r\n\r\n')
    monkeypatch.setattr(impact.socket, 'create_connection', lambda address, timeout: fake_socket)

    soap_body = (
        '<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">'
        '<s:Body><u:SetNTPServers xmlns:u="urn:dslforum-org:service:Time:1">'
        '<NewNTPServer1>pool.ntp.org</NewNTPServer1></u:SetNTPServers></s:Body></s:Envelope>'
    )
    device = DeviceConfig(name='dev1', ip='192.168.1.1')
    attack = ConfigTamperAttackConfig(
        name='config_tamper_soap',
        label='Config_Tamper_SOAP',
        port=7547,
        path='/UD/act?1',
        content_type='text/xml; charset="utf-8"',
        soap_action='urn:dslforum-org:service:Time:1#SetNTPServers',
        body=soap_body,
    )
    executor = impact.ConfigTamperExecutor(attack=attack)

    executor.execute(device=device)

    body_bytes = soap_body.encode()
    assert fake_socket.sent == (
        b'POST /UD/act?1 HTTP/1.1\r\n'
        b'Host: 192.168.1.1\r\n'
        b'Content-Type: text/xml; charset="utf-8"\r\n'
        b'SOAPAction: "urn:dslforum-org:service:Time:1#SetNTPServers"\r\n'
        + f'Content-Length: {len(body_bytes)}\r\n'.encode()
        + b'Connection: close\r\n\r\n'
        + body_bytes
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
