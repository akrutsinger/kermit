#!/usr/bin/env python3
"""Send a raw UDP NTP packet with spoofed src IP to hit the BPF filter.

The filter matches: IPv4 + UDP + src IP == 1.2.3.4
Usage: sudo python3 send_ntp.py [iface] [dst_ip]
"""

import base64
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


if __name__ == "__main__":
    main()

    p = cipher.StreamAead(nonce_len=8, tag_len=4)
    msg = b"123456"
    wire = p.seal(msg)
    print(f"message: {msg!r}  ({len(msg)} bytes)")
    print(
        f"wire   : {wire.hex()}  ({len(wire)} bytes total, {p.overhead} nonce+tag bytes)"
    )
    nonce, opened = p.open(wire)
    print(f"opened : {opened!r}  (nonce {nonce.hex()})")
    assert opened == msg

    print(f"base64 : {to_base64(wire)}")

    # a single flipped byte must be rejected
    bad = bytearray(wire)
    bad[-1] ^= 0x01
    try:
        p.open(bytes(bad))
        print("tamper : ERROR -- accepted!")
    except ValueError as e:
        print(f"tamper : rejected ({e})")
