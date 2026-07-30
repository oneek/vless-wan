# Security policy

## Supported versions

Security fixes are applied to the latest release and the `main` branch.

## Reporting a vulnerability

Do not open a public issue containing sensitive details. Use GitHub private
vulnerability reporting when it is enabled for the repository, or contact the
maintainer privately.

Include:

- the affected revision or release;
- a minimal, sanitized reproduction;
- expected and observed behavior;
- impact and suggested remediation, if known.

Remove all VLESS URLs, UUIDs, hostnames, IP addresses, post-quantum encryption
material, temporary configuration files, and process command lines from the
report. Maintainers do not need production credentials to reproduce parser or
routing defects.

## Credential exposure

Treat a VLESS share URL as a secret. If one is accidentally posted publicly,
rotate the server credential and any associated encryption material; deleting
the post does not guarantee removal from caches or Git history.
