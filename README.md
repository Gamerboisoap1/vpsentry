# VPSentry

A lightweight, self-hosted VPS security and health dashboard. Install it on Ubuntu or Debian, then open **http://SERVER_IP:8787**. One FastAPI web service serves both the compiled React frontend and the `/api` endpoints. SQLite keeps observations on your machine.

## Features

- SSH failed/successful authentication events and configurable brute-force detection.
- Passive inbound TCP SYN and UDP port-scan detection, including IPv4 and IPv6.
- Real CPU, memory, root-filesystem usage, uptime and load averages; one hour of resource history.
- Listening TCP/UDP sockets with process names when permissions allow, plus new-listener events.
- Read-only inventory of root and local users with UID 1000–65533.
- Persistent, filterable security/activity history with event details and JSON export of the current page.
- Internal VPSentry Security Score with explicit deductions and incomplete-coverage information.
- Seven responsive dark dashboard routes; no hard-coded production telemetry.
- Administrator authentication, failed-login throttling, and separate limited-capability observation services.

## Screenshots

The implemented dashboard has an overview, SSH Security, Network Scans, Open Ports, System Users, Activity Log and Attack Map. Screenshots are intentionally not populated with fictitious server data. Capture your own installation for this section; redact hostnames and addresses before sharing.

## Architecture

```text
Browser → :8787 → FastAPI
                  ├── /, /ssh, /network, /ports, /users, /activity
                  │   Compiled React + TypeScript + Tailwind + Lucide
                  └── /api/* → SQLite (/var/lib/vpsentry/vpsentry.sqlite3)
                                ↑
                      Host sampler + SSH log follower
                                ↑
                      Separate passive packet observer (CAP_NET_RAW)
                      Separate firewall snapshot timer (CAP_NET_ADMIN)
```

The web service has **no Linux capabilities**. The network observer has only `CAP_NET_RAW`. A separate, short-lived firewall inspector has `CAP_NET_ADMIN` solely to run fixed read-only `nft list ruleset`, `iptables-save`, and `ip6tables-save` commands. There are no HTTP command-execution endpoints. All services run as the dedicated `vpsentry` account. The account belongs to `adm` and `systemd-journal` to read authentication events. Application releases are root-owned; only persistent state is writable by the service account.

SQLite uses WAL mode, short transactions and independent connections. SSH attempts, deduplicated incidents and activity records share a typed event table; JSON details hold usernames, counts, first/last observation times and targeted ports. Raw authentication messages, packet payloads, passwords and keys are never stored in the event table. A state table stores monitor heartbeats, cursors and the persistent known-listener baseline. Resource samples are retained for one hour; events default to 30 days.

## Requirements

- Ubuntu 22.04+ or Debian 12+, running systemd; x86_64 or arm64.
- Root/sudo for installation, Internet access to distribution repositories, PyPI, npm and nodejs.org.
- Python 3.10+ (installed by the script). The installer supplies an isolated official Node.js 22 runtime for building the frontend.
- Approximately 1 GB available RAM for the build is a useful starting point; workload and build tooling determine actual usage. Node is not needed by the running web application.
- A VPS that permits raw packet sockets. Some restricted containers do not; coverage is reported unavailable in that case.

No Docker, reverse proxy, cloud account or separately running frontend is required. The installer does not support macOS or ordinary containers. Development on macOS works for host metrics and UI, with Linux monitoring features unavailable.

## Installation

Download or clone this complete project, then from its directory:

```bash
chmod +x install.sh
sudo ./install.sh
```

The script validates the OS and privileges; installs dependencies; creates the service account, state and configuration directories; verifies the Node archive against the vendor's HTTPS checksum manifest; builds an isolated application release as the service account; initializes SQLite; installs and enables the systemd units; starts them; and verifies the authenticated HTTP challenge and service state.

Open:

```text
http://SERVER_IP:8787
```

Your browser prompts for administrator credentials. Retrieve them on the VPS:

```bash
sudo cat /etc/vpsentry/initial-credentials
```

The password is randomly generated on the first installation. Configuration and credentials are preserved on subsequent installs. No default shared password exists. The API and frontend routes require authentication. Failed credential attempts are limited to 10 per source address per minute. Successful verification is cached in memory for up to 60 seconds; plaintext credentials are not cached.

**HTTP is unencrypted.** Use a trusted management network, an SSH tunnel, or your own HTTPS reverse proxy before sending credentials across an untrusted network. For a tunnel:

```bash
ssh -L 8787:127.0.0.1:8787 YOUR_SSH_USER@SERVER_IP
```

Then open `http://127.0.0.1:8787` locally. You can set `VPSENTRY_HOST=127.0.0.1` to make the dashboard tunnel-only. If using an HTTPS proxy, keep this loopback binding and expose only your chosen HTTPS endpoint; proxy authentication must not be used as a substitute for VPSentry's administrator authentication.

The default listener is `0.0.0.0:8787`. No additional public application ports are used. The installer does not open firewall or provider security-group rules. If your management network cannot reach the port, configure access yourself according to your policy. Automatic IP discovery uses the local route table and sends no probe to the route lookup address; behind NAT, the printed address may be private.

## Configuration

Edit `/etc/vpsentry/vpsentry.env`, then restart relevant services:

```bash
sudo systemctl restart vpsentry vpsentry-network
sudo systemctl start vpsentry-firewall
```

| Variable | Default | Meaning |
| --- | --- | --- |
| `VPSENTRY_HOST` | `0.0.0.0` | Web bind address |
| `VPSENTRY_PORT` | `8787` | Single web port |
| `VPSENTRY_DATA_DIR` | `/var/lib/vpsentry` installed | Persistent database directory |
| `VPSENTRY_FRONTEND_DIR` | `/opt/vpsentry/current/frontend/dist` installed | Production bundle |
| `VPSENTRY_ADMIN_USER` | `admin` | Administrator username |
| `VPSENTRY_PASSWORD_HASH` | Generated by installer | Salted PBKDF2-SHA256 hash, 600,000 iterations |
| `VPSENTRY_GEOIP_ENABLED` | `true` | Online lookup of public attack IPs; disable to keep all observations local |
| `VPSENTRY_GEOIP_DAILY_LIMIT` | `500` | Rolling 24-hour lookup budget |
| `VPSENTRY_SSH_SOURCE` | `journal` | `journal` or `file` |
| `VPSENTRY_AUTH_LOG` | `/var/log/auth.log` | Used with `file` source |
| `VPSENTRY_SSH_THRESHOLD` | `5` | Failures from one IP to trigger brute force (2–4096) |
| `VPSENTRY_SSH_WINDOW` | `60` | Sliding window, seconds (1–3600) |
| `VPSENTRY_SCAN_THRESHOLD` | `10` | Unique destination ports from one IP (2–4096) |
| `VPSENTRY_SCAN_WINDOW` | `60` | Scan window, seconds (1–3600) |
| `VPSENTRY_SAMPLE_SECONDS` | `5` | Host sample interval (2–300); dashboard polls every 5 seconds |
| `VPSENTRY_RETENTION_DAYS` | `30` | Event retention (1–3650) |
| `VPSENTRY_SUSPICIOUS_PORTS` | `23,3389,6379,27017` | Network-bound ports considered in score |

To change the password, generate a new hash interactively:

```bash
cd /opt/vpsentry/current
sudo .venv/bin/python -m scripts.password
sudoedit /etc/vpsentry/vpsentry.env
sudo systemctl restart vpsentry
```

Replace the `VPSENTRY_PASSWORD_HASH` entry with the generated value. Do not copy plaintext passwords into the environment file. The initial-credentials file is not updated by a password change; remove or securely update that root-only record afterward. Browsers cache HTTP Basic credentials; use a separate browser profile or close the authenticated browser session when finished on a shared computer.

Changing the data directory also requires updating `StateDirectory`/`ReadWritePaths` in systemd overrides. The supplied service confinement only allows the default state directory. Use `sudo systemctl edit vpsentry` and equivalent overrides for the observation services, then `daemon-reload`.

## Country / GeoIP lookup and attack map

Attack Map shows the latest 100 distinct attack-source IPs observed in the past 24 hours, with approximate country, city and network information. A compact map also appears on Overview. Click a marker or source row for details; filter the table by IP, country or city. Sources without a location stay visible as pending, unavailable, paused, non-public or disabled. No invented points appear when there are no recorded attacks.

The simple online option uses **ipwho.is over HTTPS** and needs no API key. Only public source IPs from detected brute-force/port-scan incidents are sent to this provider; credentials, raw logs and packet contents are not sent. The browser loads bundled country geometry, with no external map tiles or IP lookups. Geolocation belongs to the IP’s network and may reflect a proxy, VPN or hosting provider rather than the attacker’s physical location.

The background worker caches successful responses for seven days and failures for 15 minutes, limits requests to 500 per rolling 24 hours, spaces requests three seconds apart, and honors provider rate-limit backoff. Monitoring and the API do not wait for lookups. Disable external lookups with `VPSENTRY_GEOIP_ENABLED=false` and restart VPSentry; existing coordinates are hidden while disabled. `VPSENTRY_GEOIP_DAILY_LIMIT` configures the local allowance (1–1000). The [provider documentation](https://ipwhois.io/documentation) describes its free HTTPS endpoint and current usage limits; provider availability and terms can change.

`GET /api/attack-map` returns aggregated observed sources and cached locations. `GET /api/geoip?ip=ADDRESS` reads cached information and validates the IP; it never triggers arbitrary outbound lookups. Map country data comes from Natural Earth through world-atlas; see THIRD_PARTY_NOTICES.md.

## Live attack alert

Use **Test alert** beside Refresh to preview a clearly marked simulated banner for 20 seconds. **End simulation** closes it immediately. This browser-only preview writes no events, changes no scores, and never hides an actual attack alert.

A slowly pulsing red banner appears above the header on every page when an observed `SSH_BRUTE_FORCE` or `PORT_SCAN` incident has been seen within the last two minutes. Reduced-motion preferences disable the pulse. It refreshes every five seconds and clears automatically when no incident remains recent. Ongoing deduplicated incidents use their last observation time. Click an incident for details or open the activity log. If connectivity is lost, a visible banner retains the last known incidents and labels their status as stale. Port-scan detection can flag tools such as Nmap, but does not identify which scanning tool was used.

## SSH detection

A source triggers `SSH_BRUTE_FORCE` after **5 failed logins within 60 seconds**, by default. The detector recognizes common OpenSSH failed password/public-key and accepted password/public-key/keyboard-interactive messages, including invalid users and IPv6. Every recognized attempt is retained as `SSH_FAILED_LOGIN` or `SSH_SUCCESSFUL_LOGIN`, with username and source IP. Repeated threshold crossings update one ongoing incident instead of emitting a new brute-force event per attempt. Incident details expose window attempt counts and first/last times. A quiet period longer than the configured window allows a new incident.

The journal reader follows `sshd` and `sshd-session`, persists its cursor, and resumes it after restart. On first use it follows new entries rather than importing historical attacks. Missing tools, permissions or invalid/vacuumed cursors produce an unavailable status and retries. For an invalid cursor, stop the service and clear just the `ssh_journal_cursor` state entry (see troubleshooting), or select file mode. The file follower persists inode/offset and handles replacement and truncation. Detection windows themselves are held in memory; restarting can split a continuing incident, although the stored attempts and incidents remain intact.

No SSH settings change, no IP is blocked, and no user is locked out. Other authentication daemons, nonstandard log formats and some authentication methods may not match the MVP parser.

## Passive network detection

The separate `vpsentry-network` service opens a Linux `AF_PACKET` socket. It only considers inbound host-addressed frames whose destination IP is currently local to the VPS, ignores loopback and outgoing traffic, and reads headers for initial TCP SYNs and UDP datagrams. It understands Ethernet, up to two VLAN tags, IPv4 and common IPv6 extension headers. No packet payload is stored. The observer never initiates connections to another host or scans an external address.

At **10 distinct destination ports from one source within 60 seconds**, it records `PORT_SCAN`. Subsequent probes update the ongoing incident's unique port list and first/last times. Retransmissions to a single port cannot create a scan event. This catches probing of closed ports as well as open ones when packets arrive at the VPS interface. Packets filtered upstream by a provider cannot be seen.

This is an MVP heuristic, not an IDS: slow/distributed scans, fragmented traffic, unsupported encapsulations and packet loss under high traffic can evade detection; legitimate multi-port activity can trigger it. IPv6 extension traversal, per-source queues (4096 observations) and source maps (4096 active sources) are bounded. Under heavy traffic, observations may be discarded. The observer is Python-based and is not intended for line-rate packet inspection.

## VPSentry Security Score

An **internal, observational indicator**, not an industry-standard security measurement. Starts at 100:

| Condition | Deduction |
| --- | --- |
| No input firewall rules or drop policy detected | 20 |
| SSH brute-force incident in the last 24 hours | 15 |
| Port-scan incident in the last 24 hours | 10 |
| Each configured sensitive network-bound port | 5, capped at 20 |

90–100 Excellent; 75–89 Good; 50–74 Warning; 0–49 Critical. Simulation is excluded. An unavailable monitor or unknown firewall is shown as incomplete coverage; it is **not silently treated as a verified secure condition**. A high number with incomplete coverage is not evidence that a host is safe.

Firewall observation runs every minute and distinguishes configured input filtering, absent filtering, and unknown inspection. Rules being present says nothing about their correctness or coverage across IP families. New listeners start from a persistent baseline: initial inventory is not reported as newly opened; previously unseen protocol/address/port combinations create `NEW_LISTENING_PORT`. This is not vulnerability scanning.

## Services, storage and updates

```bash
sudo systemctl status vpsentry
sudo systemctl restart vpsentry
sudo systemctl stop vpsentry
sudo systemctl start vpsentry
journalctl -u vpsentry -f
sudo systemctl status vpsentry-network
sudo systemctl status vpsentry-firewall.timer
```

Stopping the web service leaves the packet observer running. To stop all observation:

```bash
sudo systemctl stop vpsentry vpsentry-network vpsentry-firewall.timer vpsentry-firewall.service
```

The enabled units restart automatically after boot. A network-observer failure is visible in the dashboard rather than silently reported healthy. Web and packet services restart after failure. The firewall inspection is periodically retried by its timer.

- Database: `/var/lib/vpsentry/vpsentry.sqlite3`, with SQLite WAL/SHM sidecars.
- Config: `/etc/vpsentry/vpsentry.env` (root-owned, service-group readable).
- Releases: `/opt/vpsentry/releases/…`, with `/opt/vpsentry/current` pointing at the selected release.
- Initial credentials: `/etc/vpsentry/initial-credentials` (root only).

To update, download/pull the new source and run `sudo ./install.sh` again. It builds before switching releases, leaves data/config intact, and attempts to restore the previous application symlink if startup fails. Keep a SQLite backup before upgrades. Old releases are retained for manual rollback; they consume disk space. The initial schema is additive; future breaking migrations need a separate backup/migration plan.

For a consistent backup, use SQLite's backup API rather than copying the database alone while WAL writers are active:

```bash
cd /opt/vpsentry/current
sudo .venv/bin/python -c "import sqlite3; source=sqlite3.connect('/var/lib/vpsentry/vpsentry.sqlite3'); target=sqlite3.connect('/root/vpsentry-backup.sqlite3'); source.backup(target); target.close(); source.close()"
```

## API

All endpoints use the same HTTP Basic administrator authentication as the UI.

| Method and endpoint | Result |
| --- | --- |
| `GET /api/health` | Version, port, monitor status, sampling status |
| `GET /api/stats` | Current host metrics and one-hour sample history |
| `GET /api/events` | Filtered, paginated security and activity events |
| `GET /api/events/recent` | Latest 8 observed events |
| `GET /api/activity` | Alias for the event timeline |
| `GET /api/ssh` | Thresholds, 24-hour counts, latest 100 incidents |
| `GET /api/scans` | Thresholds, 24-hour count, latest 100 incidents |
| `GET /api/ports` | Listener inventory and monitor status |
| `GET /api/users` | Read-only relevant local accounts |
| `GET /api/security-score` | Score, deductions, coverage and explanation |

`/api/events` accepts `category=SSH|Network|System`, `severity=INFO|LOW|MEDIUM|HIGH|CRITICAL`, `q` (up to 128 characters), `limit` (1–200), `offset` (nonnegative). Only observed events are returned. Legacy simulated rows remain excluded. The dashboard exports only its current filtered page and labels that action explicitly. Unknown API paths return JSON 404s; frontend routes return the SPA shell when refreshed directly.

## Development

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
npm --prefix frontend ci
npm --prefix frontend run build
VPSENTRY_HOST=127.0.0.1 .venv/bin/python -m backend
```

Open `http://127.0.0.1:8787`. The explicit loopback binding permits password-free local development. Public binding without a password hash fails startup. Do not use a separate uvicorn bind override to bypass the configured host; use `python -m backend`.

For optional hot reload, run `npm --prefix frontend run dev` in a separate terminal. Vite binds only to loopback and proxies `/api` to 8787. Production never runs Vite.

Development data defaults to this project's `data/` directory. The event-generation endpoint remains removed. The Test alert button only previews the banner in your browser.

## Testing and verification

```bash
npm --prefix frontend run build
.venv/bin/python -m pytest -q
bash -n install.sh
```

Tests cover SSH parsing, sliding windows, incident deduplication, file rotation and restart cursors, packet parsing/filtering, listener changes, permission errors, firewall observations, concurrent SQLite access and persistence, scoring, API authentication/validation/demo isolation, and every direct frontend route. Integration tests need permission to read local host metrics.

After installation on Linux:

```bash
cd /opt/vpsentry/current
sudo .venv/bin/python -m scripts.verify_linux
```

This verifies enabled/running services, authenticated API responses, all frontend routes, real host metrics, the network heartbeat, and persistence after restarting the web service. It uses the initial credentials file; if you have changed the password, update that root-only file before using the script. It does not conduct an attack or change SSH/firewall settings.

`.github/workflows/verify.yml` defines application tests and Ubuntu 24.04 fresh/repeated installation and service-restart checks on an ephemeral CI runner. The workflow is supplied but has not been executed by this local build. See [VERIFICATION.md](VERIFICATION.md) for the checks actually run and outstanding Linux checks. Before relying on this for a deployed host, reboot the VPS, repeat the verification, observe a real legitimate SSH login, and confirm inbound observation in an environment you control.

## Troubleshooting

- **Port unreachable:** check `systemctl status vpsentry`, the configured port/bind address, your management network, provider ACLs, and host firewall. VPSentry intentionally does not change access rules.
- **Service fails to start:** read `journalctl -u vpsentry -n 100 --no-pager`; check the environment file, hash, directory permissions and whether another service uses the port.
- **401 / browser login prompt:** use the generated administrator credentials. After changing a password, restart the service and clear cached browser credentials. **429:** wait one minute after repeated failed logins.
- **SSH unavailable:** verify `id vpsentry` includes `adm` and `systemd-journal`; try `sudo -u vpsentry journalctl -n 1`. Alternatively select `file` with a readable auth-log path. Do not make logs world-readable.
- **Journal cursor expired after vacuum:** stop VPSentry, use Python/SQLite to delete only the `state` row with key `ssh_journal_cursor`, then restart. Monitoring resumes from the current time; the unobserved gap is not reconstructed. Previously stored events remain.
- **Network unavailable:** check `journalctl -u vpsentry-network`; Linux raw-socket support and the supplied capability settings are required. macOS and restricted containers are not supported packet-observer environments.
- **Firewall unknown:** inspect `journalctl -u vpsentry-firewall` and the timer. Unknown is shown when inspection fails; it is not the same as inactive.
- **Missing process names:** normal without permission to inspect another user's processes. The port and address can still be present. macOS usually restricts system-wide socket inventory; the Linux service is the deployment target.
- **Stale metrics:** the UI displays request errors and sampling timestamps. Check service logs, memory/disk pressure and state-directory write access.
- **Installer build failure:** check Internet access, free memory, disk space and the reported build step. Existing data/config are preserved. If a repeat install fails before switching, the old application keeps running.

## Uninstallation

Stop and disable the units, then remove application files. Keep `/var/lib/vpsentry` and `/etc/vpsentry` if you may reinstall:

```bash
sudo systemctl disable --now vpsentry vpsentry-network vpsentry-firewall.timer
sudo systemctl stop vpsentry-firewall.service
sudo rm /etc/systemd/system/vpsentry.service /etc/systemd/system/vpsentry-network.service /etc/systemd/system/vpsentry-firewall.service /etc/systemd/system/vpsentry-firewall.timer
sudo systemctl daemon-reload
sudo rm -rf /opt/vpsentry
```

Only when you intentionally want to delete all event history and credentials:

```bash
sudo rm -rf /var/lib/vpsentry /etc/vpsentry
sudo userdel vpsentry
```

Distribution packages are left installed because other applications may use them. VPSentry never installed firewall or SSH policy rules to undo.

## Security limitations

This MVP detects and records; it does not prevent attacks, audit package vulnerabilities, guarantee security, or replace host patching, SSH hardening, backups and firewall administration. Local compromise of the service account can tamper with observations. Basic authentication requires transport protection on untrusted networks and offers one administrator account, no MFA or role separation. Reverse proxies should preserve same-origin API requests; forwarded IP headers are deliberately not trusted, so failed-login limits behind a proxy may be shared by its clients. Hostnames, account inventories and IP addresses are sensitive operational data; protect backups and exported events accordingly.
