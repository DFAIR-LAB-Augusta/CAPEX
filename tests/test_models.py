from __future__ import annotations

from ipaddress import IPv4Address

from capex.models import CommandAttackConfig, DeviceConfig, DnsTunnelExfilAttackConfig


def test_device_config_validates() -> None:
    device = DeviceConfig(name='nestCam', ip=IPv4Address('192.168.1.196'))
    assert device.name == 'nestCam'


def test_attack_config_validates() -> None:
    attack = CommandAttackConfig(
        name='udp_flood',
        label='UDP_Flood',
        command=['hping3', '--udp', '-c', '100', '-p', '53', '{target_ip}'],
    )
    assert attack.repeats == 3


def test_dns_tunnel_exfil_attack_config_defaults() -> None:
    attack = DnsTunnelExfilAttackConfig(name='dns_tunnel_exfil', label='DNS_Tunnel_Exfil')
    assert attack.payload_size_bytes == 512
    assert attack.base_domain == 'exfil.example'
