# Verification record

Local verification performed on 10 September 2026, macOS arm64, Python 3.13 and Node 20.20.2.

## Passed locally

- React/TypeScript production compilation and Vite build. The FastAPI process serves this bundle at port 8787; there is no separate frontend process.
- **44 pytest tests passed**. One third-party Starlette/AnyIO deprecation warning remains; it does not affect the assertions or application runtime.
- Tests cover all API routes, validated query/body inputs, administrator challenge/credentials, failed-login throttling, public-startup rejection without authentication, and no unknown command/event types.
- Production demo rejection, simulated/observed query separation, and exclusion of simulated incidents from the real score/counts.
- SSH thresholds, source separation, time windows, IPv6 and successful-login parsing, incident deduplication and first/last observation details.
- Real temporary auth-file following, persistent cursor resume, file rotation, missing-log status and graceful stop.
- IPv4/IPv6, TCP SYN vs SYN/ACK, UDP, VLAN, truncated/fragmented packets and local-destination filtering using synthetic packet headers. No external host was scanned.
- Listening socket mapping, new-port baseline/persistence, and permission-failure handling using controlled fixtures.
- Read-only firewall result classification using controlled command outputs.
- Concurrent SQLite writes, persistent reopen, filtering, pagination, retention and score deductions.
- Real local host metrics, FastAPI process startup, actual HTTP requests, process termination/restart and database survival. Real-process test uses a temporary loopback port; the interactive preview binds **127.0.0.1:8787**.
- Frontend shell served correctly on direct requests to `/`, `/ssh`, `/network`, `/ports`, `/users`, `/activity`; unknown API routes return 404.
- Browser inspection of desktop and 390px mobile layouts; mobile page width did not overflow. Mobile navigation, safe event generation, simulated badge/origin, event details, and search interactions were checked. No browser console warnings/errors were observed during these interactions.
- `bash -n install.sh` and ShellCheck 0.11 passed. Running the installer on macOS correctly refuses before making system changes.

## Not verified on this host

This host has no Linux VM/container runtime or systemd. Accordingly, the following are **not claimed as passed**:

1. A fresh Ubuntu/Debian installation with apt and systemd.
2. Real AF_PACKET capture under the supplied systemd capability restrictions.
3. Real systemd-journal SSH ingestion and host firewall inspection under the service account.
4. Startup after a real VPS reboot.
5. Repeated installation/rollback on Linux.

The implementation includes `scripts/verify_linux.py` for installed-service/restart verification and `.github/workflows/verify.yml` for Ubuntu 24.04 fresh and repeated installation checks. These Linux checks have been supplied, not executed here. Debian and arm64 installation also need actual deployment validation.

## Interpretation

The UI uses live host data. Linux-only monitors show unavailable on this macOS preview, rather than simulated healthy status. The local preview no longer includes simulation controls or a simulation endpoint. Legacy simulated rows in gitignored local development data remain excluded from public queries and from every installed release.

The requested full fresh-VPS → install → dashboard → reboot definition of done remains dependent on the above Linux deployment checks. The project is implemented and locally tested, but this record is not a claim of production certification or a completed live-VPS deployment.

## Production preparation update

Simulation controls, the generation endpoint and the demo environment setting have been removed at the user’s request. Existing simulated database rows remain excluded from all public event queries and scoring. The regression tests now verify this legacy-data isolation and rejection of the removed endpoint.

## 11 September 2026 — pulsing alerts and GeoIP attack map

- Production TypeScript/Vite build passed with bundled world-country geometry and map projections.
- Full regression suite: **70 passed**. After adding the trusted CA certificate bundle, all 19 GeoIP-specific cases were rerun and passed.
- Verified a real HTTPS lookup against ipwho.is for the public DNS address 8.8.8.8: a valid location result was returned. This was a provider smoke test only and did not create an attack or write a production event.
- Checked private/reserved/multicast/scoped-IP exclusion, provider IP/coordinate validation, rolling daily allowance, 429 backoff, negative caching, disabled enrichment, cache persistence and aggregation of ongoing incidents.
- The /attack-map route and /api/attack-map and cache-only /api/geoip endpoints passed integration checks, including excluding legacy simulated data.
- Browser checks: Attack Map navigation, local world rendering, honest empty state, 390px mobile layout without horizontal overflow, and Test alert animation (`attack-pulse`) with working dismissal. Pulse CSS is enabled only under `prefers-reduced-motion: no-preference`.
- No fabricated attacks were inserted into the local preview. GeoIP remains an approximate external-network lookup, not attacker identification. Linux deployment/reboot checks listed above remain outstanding.
