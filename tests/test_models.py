from __future__ import annotations

from ipaddress import IPv4Address

from capex.models import C2BeaconAttackConfig, C2DnsBeaconAttackConfig, CommandAttackConfig, DeviceConfig


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


def test_c2_beacon_attack_config_defaults() -> None:
    attack = C2BeaconAttackConfig(name='c2_beacon', label='C2_Beacon')
    assert attack.jitter_seconds == 5
    assert attack.path == '/'


def test_c2_dns_beacon_attack_config_defaults() -> None:
    attack = C2DnsBeaconAttackConfig(name='c2_dns_beacon', label='C2_DNS_Beacon')
    assert attack.port == 53
    assert attack.domain == 'update-check.example'
