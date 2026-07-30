# Contributing

Thank you for helping improve `vless-wan`.

## Before opening an issue

Search existing issues and reproduce the problem with the latest revision.
Never include a real VLESS URL, UUID, server address, encryption key, hostname,
or unsanitized process listing. Replace sensitive values with documentation
examples such as `example.com`, `192.0.2.1`, and a clearly fake UUID.

## Development workflow

1. Fork the repository and create a focused branch.
2. Make a small, reviewable change.
3. Add or update tests.
4. Run `make verify`.
5. Use clear commit messages and explain user-visible behavior in the pull
   request.

The unit test suite must not require root, create network interfaces, or make
network requests. Integration testing that changes routes must be opt-in and
must restore the original system state.

## Style

- Format Go code with `gofmt`.
- Prefer the Go standard library.
- Return contextual errors instead of logging and continuing.
- Keep platform-specific behavior isolated and test pure route/config
  generation separately.
- Do not commit generated binaries, downloaded Xray payloads, credentials, or
  local configuration.

## Reporting security issues

Follow [SECURITY.md](SECURITY.md) instead of opening a public issue.
