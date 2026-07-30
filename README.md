# vless-wan

`vless-wan` turns a VLESS share link into a temporary Linux VPN. It embeds
[Xray-core](https://github.com/XTLS/Xray-core), creates a TUN interface, and
offers a command line inspired by [sshuttle](https://github.com/sshuttle/sshuttle).

The process stays in the foreground. Press `Ctrl+C` to stop Xray and remove the
routes installed by `vless-wan`.

> [!WARNING]
> This project is experimental networking software. Keep an SSH recovery
> session open when testing it on a remote host.

## Features

- one distributable binary with an embedded, checksum-pinned Xray-core;
- full-tunnel or selected CIDR/domain routing;
- IPv4 and IPv6 support;
- repeatable route exclusions;
- optional DNS interception through VLESS;
- TLS, REALITY, TCP, WebSocket, gRPC, HTTP Upgrade, Vision, and VLESS
  post-quantum encryption share-link parameters;
- deterministic route cleanup on normal termination.

## Requirements

- Linux;
- root privileges or equivalent TUN and route capabilities;
- `ip` from iproute2 at runtime;
- Go 1.22+, `curl`, `unzip`, and `sha256sum` when building from source.

## Build

```sh
git clone https://github.com/oneek/vless-wan.git
cd vless-wan
make build
```

The binary is written to `dist/vless-wan`. The build downloads the Xray-core
version pinned in `scripts/fetch-xray.sh`, verifies its SHA-256 checksum, and
embeds it into the executable. The downloaded payload and build products are
ignored by Git.

Run the local verification suite without downloading Xray:

```sh
make verify
```

## Usage

Route all IPv4 and IPv6 traffic and intercept DNS:

```sh
sudo ./dist/vless-wan --dns \
  -r 'vless://00000000-0000-4000-8000-000000000000@example.com:443?security=tls&type=tcp' \
  0/0 ::/0
```

Route selected networks and a domain:

```sh
sudo ./dist/vless-wan --dns \
  -r 'vless://00000000-0000-4000-8000-000000000000@example.com:443?security=tls&type=tcp' \
  10.0.0.0/8 2001:db8:1234::/48 internal.example
```

Exclude destinations with the repeatable `-x` flag:

```sh
sudo ./dist/vless-wan --dns \
  -x 192.168.0.0/16 \
  -x direct.example \
  -r 'vless://00000000-0000-4000-8000-000000000000@example.com:443?security=tls&type=tcp' \
  0/0 ::/0
```

Use a custom DNS upstream:

```sh
sudo ./dist/vless-wan --dns --to-ns 9.9.9.9:53 \
  -r 'vless://00000000-0000-4000-8000-000000000000@example.com:443?security=tls&type=tcp' \
  0/0
```

Options must precede the positional routes. Run `vless-wan --help` for the
complete reference.

### Inspect and validate

Generate the Xray JSON without starting a tunnel:

```sh
./dist/vless-wan config --all 'vless://...'
```

Ask the embedded Xray-core to validate generated JSON:

```sh
./dist/vless-wan check --all 'vless://...'
```

### Confirm routing

While `vless-wan` is running, use a second terminal:

```sh
ip route get 203.0.113.1
ip -6 route get 2001:db8::1
```

Full-tunnel mode installs two split-default routes per address family. They are
more specific than the existing default route without replacing it:

```text
0.0.0.0/1
128.0.0.0/1
::/1
8000::/1
```

## Security notes

- A VLESS share link is a credential. Do not commit it, paste it into issue
  reports, or publish diagnostic process listings containing it.
- Command-line arguments may be visible to other local users through process
  inspection. Use this tool only on hosts whose local users you trust.
- `--insecure` disables certificate verification and should only be used for
  controlled troubleshooting.
- Generated configurations are written to a mode `0600` temporary directory
  and removed when the wrapper exits normally.

## Limitations

- Domain-only routing depends on Xray protocol sniffing. Also provide CIDRs for
  applications using encrypted DNS or protocols without a sniffable hostname.
- Abrupt power loss or `SIGKILL` prevents userspace cleanup. TUN-associated
  routes normally disappear with the interface; inspect the routing table
  before restarting.
- The release payload currently targets Linux amd64.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md). Bug reports that may contain share
links, UUIDs, server addresses, or encryption material must be sanitized before
submission.

## License

The wrapper is available under the MIT License. Embedded Xray-core is licensed
separately under MPL-2.0. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
