# kermit

`listen` waits for inbound UDP from `1.2.3.4`; `holla.py` sends it one.

## Build the listener

```sh
cargo build -p listen
```

Use the debug build: `listen` only prints in debug builds.

## Run it

In one terminal, start the listener (raw sockets need root):

```sh
sudo ./target/debug/listen
```

In another, send a packet with `holla.py`. It needs [uv](https://docs.astral.sh/uv/), which reads
the script's dependencies (scapy, cryptography) from its header and installs them on first run:

```sh
sudo uv run holla.py            # defaults: interface lo, destination = lo's address
sudo uv run holla.py eth0 10.0.0.5
```

## What you should see

`holla.py` prints the packet it sent, then a local crypto self-test:

```
Sending NTP packet: 1.2.3.4:12345 -> 127.0.0.1:123 via lo
.
Sent 1 packets.
...
```

`listen` prints the matched frame's size (Ethernet + IP + UDP + 48-byte NTP payload), then, a few
seconds later, that its handler finished:

```
matched: 90 bytes
done processing packet
```

Each handled packet also records a nonce in the replay ring at `/tmp/nonce` (33 bytes: a 1-byte head
plus 4 slots of 8 bytes, encrypted). To watch it change, run this in a third terminal:

```sh
sudo watch -d -n 0.5 xxd /tmp/nonce
```

The file appears with the first handled packet. Each packet after that changes the first byte (the
head) and one 8-byte slot; after 4 packets it wraps around.

Packets from any other source address are ignored. (The `holla/` crate is a separate REPL
prototype and doesn't send packets yet.)
