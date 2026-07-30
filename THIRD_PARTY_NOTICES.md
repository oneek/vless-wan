# Third-party notices

## Xray-core

Release builds produced by this repository embed an official Xray-core binary.

- Project: <https://github.com/XTLS/Xray-core>
- License: Mozilla Public License 2.0
- Pinned version and archive checksum: `scripts/fetch-xray.sh`
- Source releases: <https://github.com/XTLS/Xray-core/releases>

Xray-core is not stored in this Git repository. The build helper downloads the
official release archive and verifies its pinned SHA-256 checksum before
embedding the executable.

The MIT license in this repository applies only to the `vless-wan` wrapper and
does not replace or modify the license of Xray-core.
