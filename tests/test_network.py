import socket
import struct
import pytest
from backend.monitors.network import parse_packet


def packet(protocol=6, flags=2, ipv6=False):
    ethernet = b'\x00'*12 + struct.pack('!H', 0x86dd if ipv6 else 0x0800)
    if ipv6:
        ip = struct.pack('!IHBB16s16s', 6 << 28, 20, protocol, 64, socket.inet_pton(socket.AF_INET6,'2001:db8::1'), socket.inet_pton(socket.AF_INET6,'2001:db8::2'))
    else:
        ip = struct.pack('!BBHHHBBH4s4s', 0x45,0,40,0,0,64,protocol,0,socket.inet_aton('192.0.2.5'),socket.inet_aton('192.0.2.6'))
    tcp = struct.pack('!HHIIBBHHH', 50000,8787,0,0,5 << 4,flags,0,0,0)
    return ethernet+ip+tcp

@pytest.mark.parametrize('ipv6', [False, True])
@pytest.mark.parametrize('protocol', [6,17])
def test_inbound_headers(ipv6, protocol):
    assert parse_packet(packet(protocol=protocol, ipv6=ipv6)) == ('2001:db8::1' if ipv6 else '192.0.2.5',8787)

@pytest.mark.parametrize('flags',[0,16,18,4])
def test_only_initial_syn(flags):
    assert parse_packet(packet(flags=flags)) is None

def test_truncated_and_fragmented():
    value=packet()
    for n in range(54):
        assert parse_packet(value[:n]) is None
    frame=bytearray(value)
    frame[20:22]=b'\x00\x01'
    assert parse_packet(frame) is None
    assert parse_packet(packet(protocol=1)) is None

def test_vlan():
    value=packet()
    frame=value[:12]+b'\x81\x00\x00\x01\x08\x00'+value[14:]
    assert parse_packet(frame)==('192.0.2.5',8787)
