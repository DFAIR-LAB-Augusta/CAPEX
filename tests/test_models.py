from __future__ import annotations

from ipaddress import IPv4Address

from capex.models import ArpSpoofAttackConfig, CommandAttackConfig, DeviceConfig


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


def test_arp_spoof_attack_config_defaults() -> None:
    attack = ArpSpoofAttackConfig(name='arp_spoof', label='ARP_Spoof', interface='eth0', gateway_ip='192.168.1.1')
    assert attack.duration_seconds == 30
    assert attack.arpspoof_binary == 'arpspoof'
