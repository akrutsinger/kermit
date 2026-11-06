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

Packets from any other source address are ignored. (The `holla/` crate is a separate REPL
prototype and doesn't send packets yet.)
