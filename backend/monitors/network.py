"""Linux AF_PACKET observer. Only incoming TCP SYN and UDP headers are inspected.
Runs separately with CAP_NET_RAW; no capture payloads are stored or served.
"""
import ipaddress
import signal
import socket
import struct
import time
import psutil
from backend.config import settings
from backend.models.store import Store
from backend.monitors.detection import Detector


def parse_packet(frame, local_addresses=None):
    if len(frame) < 14:
        return None
    ether, offset = struct.unpack_from('!H', frame, 12)[0], 14
    for _ in range(2):
        if ether in (0x8100, 0x88a8) and len(frame) >= offset + 4:
            ether = struct.unpack_from('!H', frame, offset + 2)[0]
            offset += 4
    if ether == 0x0800:
        if len(frame) < offset + 20 or frame[offset] >> 4 != 4:
            return None
        size = (frame[offset] & 15) * 4
        if size < 20 or len(frame) < offset + size or struct.unpack_from('!H', frame, offset + 6)[0] & 0x1fff:
            return None
        protocol = frame[offset + 9]
        source = str(ipaddress.ip_address(frame[offset + 12:offset + 16]))
        destination = str(ipaddress.ip_address(frame[offset + 16:offset + 20]))
        offset += size
    elif ether == 0x86dd:
        if len(frame) < offset + 40:
            return None
        protocol = frame[offset + 6]
        source = str(ipaddress.ip_address(frame[offset + 8:offset + 24]))
        destination = str(ipaddress.ip_address(frame[offset + 24:offset + 40]))
        offset += 40
        # Skip common IPv6 extension headers with a strict bound.
        for _ in range(8):
            if protocol not in (0, 43, 60, 44):
                break
            if len(frame) < offset + 8:
                return None
            next_protocol = frame[offset]
            if protocol == 44:
                if struct.unpack_from('!H', frame, offset + 2)[0] & 0xfff8:
                    return None
                size = 8
            else:
                size = (frame[offset + 1] + 1) * 8
            protocol, offset = next_protocol, offset + size
    else:
        return None
    if local_addresses is not None and destination not in local_addresses:
        return None
    if protocol == 6:
        if len(frame) < offset + 20 or frame[offset + 13] & 0x12 != 0x02:
            return None
    elif protocol == 17:
        if len(frame) < offset + 8:
            return None
    else:
        return None
    return source, struct.unpack_from('!H', frame, offset + 2)[0]


def main():
    store = Store(settings.data_dir)
    detector = Detector(store, settings)
    stopped = False
    def stop(*_):
        nonlocal stopped
        stopped = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as capture:
            capture.settimeout(1)
            updated = 0
            local_addresses = set()
            while not stopped:
                if time.time() - updated > 5:
                    updated = time.time()
                    local_addresses = {a.address.split('%')[0] for addresses in psutil.net_if_addrs().values() for a in addresses if a.family in (socket.AF_INET, socket.AF_INET6)}
                    store.set('network_status', {'state': 'active', 'message': 'Passive inbound TCP SYN / UDP monitoring', 'updated': updated})
                try:
                    frame, address = capture.recvfrom(512)
                except socket.timeout:
                    continue
                # PACKET_HOST only: excludes outgoing, forwarded-otherhost and broadcast traffic.
                if address[2] != 0 or address[0] == 'lo':
                    continue
                parsed = parse_packet(frame, local_addresses)
                if parsed:
                    detector.probe(*parsed)
    except (OSError, AttributeError) as exc:
        store.set('network_status', {'state': 'unavailable', 'message': str(exc)[:180], 'updated': time.time()})
        raise SystemExit(1)
    finally:
        store.set('network_status', {'state': 'unavailable', 'message': 'Packet observer stopped', 'updated': time.time()})

if __name__ == '__main__':
    main()
