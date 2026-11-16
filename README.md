# vless-wan

`vless-wan` turns a VLESS share link into a temporary Linux VPN. It embeds
[Xray-core](https://github.com/XTLS/Xray-core), creates a TUN interface, and
offers a command line inspired by [sshuttle](https://github.com/sshuttle/sshuttle).

The process stays in the foreground. Press `Ctrl+C` to stop Xray and remove the
routes installed by `vless-wan`.

> [!WARNING]
> This project is experimental networking software. Keep
> console or out-of-band recovery access available when testing on a remote host.

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
- root privileges or equivalent TUN, route, and socket-mark capabilities;
- `ip` from iproute2 at runtime;
- Go 1.22+, `curl`, `unzip`, and `sha256sum` when building from source.

Before starting Xray, the wrapper verifies Linux support, `iproute2`,
`/dev/net/tun`, `CAP_NET_ADMIN`, and TUN interface availability. Missing
requirements produce an immediate error instead of waiting for Xray startup.

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

### Routing and incoming services

`vless-wan` leaves the main routing table unchanged. It creates a separate VPN
routing table and policy rules for locally originated traffic, without nftables
or conntrack. Full-tunnel mode uses a default route in that separate table;
selected CIDRs use individual routes. New connections select the TUN source
address when their destination is routed through the VPN.

Packets with a source address belonging to an ordinary host interface use the
main table. This keeps existing TCP sessions and replies from SSH, HTTP, and
other services on their original network, including connections accepted after
the VPN starts. Applications explicitly bound to an ordinary host IP also bypass
the VPN. Connected local networks and CIDR exclusions remain direct. Domain
exclusions are handled by Xray; Xray's own outbound sockets bypass the VPN using
`SO_MARK` (`0x56000000`) and automatic outbound interface binding.

To inspect the selected path, compare an unbound lookup with a lookup explicitly
using your ordinary host IP:

```sh
ip route get 203.0.113.1
ip route get 203.0.113.1 from YOUR_HOST_IP
ip rule show
ip -6 rule show
```

This version supports one instance per network namespace, standard Linux policy
rules, and stable host addresses/uplinks. Existing custom policy rules cause an
error before routing is changed. Restart after host address or uplink changes.
Forwarded traffic from containers or other machines is not routed into the VPN.
This is not a kill switch: stopping the VPN restores ordinary outgoing routing.

The wrapper selects an unused table in `20000..20099`. It logs each family's
bypass priority range (starting at `10000`) and uses priority `32765` for VPN
selection. Rules are removed before Xray stops, including on partial startup
failure. Only the new TUN interface's reverse-path filtering is adjusted; global
network sysctls are unchanged.

### Recovery after an unclean exit

`SIGKILL` prevents wrapper cleanup. The child normally terminates with its parent,
and TUN routes disappear with the interface, but policy rules and direct-network
`throw` routes can remain. A later launch rejects leftover policy rules.

With no wrapper or Xray instance still running, inspect `ip -4 rule show` and
`ip -6 rule show`. Remove only this instance's rules using its logged priorities,
starting with the VPN selection rule:

```sh
sudo ip -4 rule del pref 32765
sudo ip -6 rule del pref 32765
# Repeat for each bypass priority logged for the corresponding family:
sudo ip -4 rule del pref PRIORITY
sudo ip -6 rule del pref PRIORITY
# Use the table number logged by this instance:
sudo ip -4 route flush table TABLE_ID
sudo ip -6 route flush table TABLE_ID
```

Do not delete rules or flush tables owned by other software.

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
- Unclean termination may require policy-rule cleanup; see recovery above.
- The release payload currently targets Linux amd64.

## Development

Run `make verify` for formatting, race-enabled unit tests, and vet. Run
`sudo make integration` for isolated IPv4/IPv6 routing and TCP/UDP tests; this
requires `unshare` and `nsenter` from util-linux. With an embedded Xray payload,
the suite also tests real TUN-to-VLESS forwarding and graceful shutdown, without
accessing the public network. The integration test refuses to run in a namespace
containing host interfaces.

See [CONTRIBUTING.md](CONTRIBUTING.md). Bug reports that may contain share
links, UUIDs, server addresses, or encryption material must be sanitized before
submission.

## License

The wrapper is available under the MIT License. Embedded Xray-core is licensed
separately under MPL-2.0. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Inspired by

This project is inspired by tools that make transparent proxying and selective
routing practical from the command line:

- [sshuttle](https://github.com/sshuttle/sshuttle) — a transparent proxy and
  VPN-like tool built around SSH;
- [Wirez](https://github.com/v-byte-cpu/wirez) — a utility for redirecting TCP and
  UDP traffic through a SOCKS5 proxy.
