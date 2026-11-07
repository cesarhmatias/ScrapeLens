# Real-Chrome flood through the relay (Linux)

A stranger process floods the relay with connections while Chrome loads a page through it.
The check is whether the page completes: 240 images and one slow resource, reported by the page as
`ok=241 err=0`.

## Files

- `realchrome.py`: starts the relay (`examples/relay_server.rs`), Chrome with a temporary profile
  through the relay as SOCKS5, the local page server, and the flood. Prints the page result and the
  relay's failures.
- `flooder.c`: the stranger. Each thread connects, holds sockets for a time, then resets them.
- `run.sh`: runs the check N times and prints the number of complete pages.

## Run

```
cd capture && cargo build --example relay_server
bash experiments/relay-flood/run.sh target/debug/examples/relay_server 10
```

Linux only. The relay runs as uid 1000 and the flood as uid 2000, so both users must exist or the
process must be able to switch to them. Chrome needs `--security-opt seccomp=unconfined` and a
larger `/dev/shm` when it runs in a container (`--shm-size=1g`).

## Reference (review-013b, same machine)

| Build | Complete pages, 10 runs |
|---|---|
| 027a598 (four generations) | 6 / 10 |
| one generation | 9 / 10 |
| one generation and the oldest-waiter cancel | 10 / 10 |

At a descriptor soft limit of 1024 (`RELAY_NOFILE=1024`) the relay completes fewer pages,
whatever the build. The App must raise the soft limit at startup.
