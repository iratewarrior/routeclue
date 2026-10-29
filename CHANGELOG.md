# Changelog

## 0.1.0

- Kill switch on pf: rules bound to the tunnel core's uid, server address independent.
- Route healing for private subnets with `-ifscope`.
- Split DNS zones via `/etc/resolver`.
- Diagnostics with real DNS probes and exit-address detection.
- CLI and menu bar app sharing one core.
- Unit tests for ruleset generation, DNS parsing and configuration.
