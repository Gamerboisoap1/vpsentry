# VPSentry

VPSentry is a small Linux VPS security and health dashboard. It shows system load, SSH activity, listening ports, suspicious port scans, recent events and an approximate GeoIP attack map.

## Run it on your VPS

Use Ubuntu 22.04+, Debian 12+, or a newer compatible release.

```bash
git clone https://github.com/Gamerboisoap1/vpsentry.git
cd vpsentry
chmod +x RUN
sudo ./RUN
```

The first run installs missing tools, prepares Python, downloads frontend packages and builds the website. Later runs reuse that setup.

The terminal prints an address like:

```text
http://YOUR_SERVER_IP:8787
```

Open that address in your browser. There is no login screen. Keep the terminal open while using VPSentry. Press `Ctrl+C` to stop the dashboard and its network observer.

If the page does not open, allow TCP port `8787` in your VPS provider firewall or Linux firewall. VPSentry does not change firewall rules.

## Update it

Stop VPSentry with `Ctrl+C`, then run:

```bash
git pull
sudo ./RUN
```

## What `RUN` does

- Binds the website to `0.0.0.0:8787` so it is reachable at the server IP.
- Runs in the foreground and stops with `Ctrl+C`.
- Uses root so it can read SSH logs, inspect firewall state and passively observe incoming connection attempts.
- Stores observations in `data/vpsentry.db` so they remain available next time.
- Sends public attack-source IPs to `ipwho.is` for approximate GeoIP data. Set `VPSENTRY_GEOIP_ENABLED=false` before running if you do not want that lookup.

## Temporary dashboard warning

There is intentionally no authentication. Anyone who can reach port `8787` can view the dashboard and its server information. Only open the port while you are using it, restrict it to your own IP when possible, and press `Ctrl+C` when finished.

VPSentry observes and reports activity. It does not block IP addresses, change SSH settings, or replace normal VPS updates, SSH hardening, backups and firewall rules.

## Optional permanent install

`sudo ./install.sh` installs VPSentry as a systemd service. The same no-login dashboard is then available on port `8787`. Stop it with:

```bash
sudo systemctl stop vpsentry vpsentry-network
```
