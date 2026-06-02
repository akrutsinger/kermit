#!/usr/bin/env python3
"""Send a raw UDP NTP packet with spoofed src IP to hit the BPF filter.

The filter matches: IPv4 + UDP + src IP == 1.2.3.4
Usage: sudo python3 send_ntp.py [iface] [dst_ip]
"""

import base64
import os
import sys

from scapy.all import IP, UDP, Ether, Raw, get_if_addr, sendp

import cipher


def ntp_client_payload() -> bytes:
    # NTP v4 client request: LI=0, VN=4, Mode=3 — 48 bytes total
    li_vn_mode = (0 << 6) | (4 << 3) | 3
    return bytes([li_vn_mode]) + bytes(47)


def main() -> None:
    iface = sys.argv[1] if len(sys.argv) > 1 else "lo"
    dst_ip = sys.argv[2] if len(sys.argv) > 2 else get_if_addr(iface)
    src_ip = "1.2.3.4"
    sport = 12345
    dport = 123

    pkt = (
        Ether()
        / IP(src=src_ip, dst=dst_ip)
        / UDP(sport=sport, dport=dport)
        / Raw(ntp_client_payload())
    )

    print(f"Sending NTP packet: {src_ip}:{sport} -> {dst_ip}:{dport} via {iface}")
    sendp(pkt, iface=iface, verbose=True)


def to_base64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def prepend_nonce(msg: bytes, n: int = 8) -> bytes:
    """Application framing: append `n` random replay-nonce bytes to the message.
    Done by the caller before sealing, never inside the crypto layer."""
    return os.urandom(n) + msg


if __name__ == "__main__":
    # main()

    p = cipher.SivCipher(n=4)
    framed = prepend_nonce(b"123456")  # msg || 8-byte app nonce
    wire = p.seal(framed)
    print(f"framed : {framed!r}  ({len(framed)} bytes)")
    print(
        f"wire   : {wire.hex()}  ({len(wire)} bytes total, {p.n} prepended tag bytes)"
    )
    print(f"opened : {p.open(wire)!r}")
    assert p.open(wire) == framed

    print(f"base64 : {to_base64(wire)}")

    # a single flipped byte must be rejected
    bad = bytearray(wire)
    bad[-1] ^= 0x01
    try:
        p.open(bytes(bad))
        print("tamper : ERROR -- accepted!")
    except ValueError as e:
        print(f"tamper : rejected ({e})")
