# VPSentry
<!-- impeccable:product-schema 1 -->
## Platform
web
## Stack
FastAPI, Python, SQLite, React, TypeScript, Tailwind CSS and Lucide, as requested. React selected from the brief's permitted alternatives.
## Users
Linux VPS administrators monitoring their own Ubuntu/Debian machine.
## Product Purpose
Run one foreground launcher, open port 8787, observe real security activity and host health, then stop it with Ctrl+C.
## Capabilities and Constraints
Read-only SSH detection, passive inbound network detection, host metrics, ports, local users, persistent events. No blocking, scanning other hosts, or account mutations. The public temporary dashboard intentionally has no login.
## Brand Commitments
VPSentry. Responsive dark cybersecurity dashboard with restrained charcoal and mint, readable dense tables. User approved building directly in code.
## Product Principles
Honest monitoring coverage; preserve data across upgrades; simple single-port operation; reliable installation.

## Attack location enrichment
User selected the easier online GeoIP option. Public attack-source IPs are sent to ipwho.is with caching and limits; disable in configuration. Display approximate country/network origin in a local world map. Alerts pulse slowly and respect reduced motion.
