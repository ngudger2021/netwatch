# Kali NetWatch

Network discovery, inventory, change detection and non-intrusive security auditing for a
Kali Linux Raspberry Pi. Built on Python 3 (FastAPI), SQLite, Nmap, Bootstrap 5 and Chart.js.
No paid services are required.

> **Authorisation.** Scan only networks you own or are explicitly authorised to test.
> Only the networks in `[networks]` (and enabled in the dashboard) can ever be scanned.

## Contents
1. [What it does](#what-it-does)
2. [Quick start (development)](#quick-start-development)
3. [Installing on the Raspberry Pi](#installing-on-the-raspberry-pi)
4. [Configuration](#configuration)
5. [Telegram notifications](#telegram-notifications)
6. [Security model](#security-model)
7. [Exposing the dashboard](#exposing-the-dashboard)
8. [Operations: upgrade, backup, recovery](#operations-upgrade-backup-recovery)
9. [API](#api)
10. [Tests](#tests)
11. [Project layout](#project-layout)
12. [Known limitations](#known-limitations)

---

## What it does

| Area | Implementation |
|---|---|
| Discovery | Nmap `-sn` with TCP connect probes (unprivileged) or ICMP/ARP (privileged mode) |
| Ports & services | `-sT` with `--top-ports` (standard) or explicit ranges (detailed/custom) and `-sV` |
| MAC addresses | Nmap output, plus the kernel neighbour table **only for directly attached subnets** |
| Identity | MAC is authoritative; heuristic merges need a score ≥ 70 (see below) |
| Change detection | new, returning, offline, IP change, hostname change, port opened/closed/reopened, service change |
| Offline logic | A device goes offline only after *N* consecutive **successful** full-network scans with it absent (default 3). Failed, cancelled or partial scans never count |
| Security findings | Telnet, FTP, plain-HTTP admin, SMBv1 (script-evidence only), exposed database, RDP, VNC, WinRM, IPMI; SSH is info-only |
| Risk score | 0–100 = sum of weights of open findings, capped at 100. Trust never hides or reduces findings |
| Scheduling | Quick discovery every 15 min, standard scan every 6 h, daily Telegram summary; manual detailed/custom scans |
| Web UI | Dark responsive dashboard, inventory with filters and sorting, device pages, scans, findings, events, reports, settings, Pi health |
| API | JSON under `/api/v1`, OpenAPI docs at `/api/docs` |
| Reports | CSV, JSON or HTML for inventory, ports, findings, changes, statistics |

### Device identity rules
1. A real (non-randomised) MAC address identifies the device. Same MAC means same device, whatever the IP.
2. Two devices with different real MACs are never merged.
3. A device without a stable MAC, or with a randomised one, can be matched to a new observation only if the score reaches 70:
   same IP and network +50, same hostname +40, same vendor +15, seen within 7 days +15.
   Hostname and network alone (60) do not merge. Each merge is recorded as an event.
4. Without a MAC, an observation matches a MAC-less device only at the same IP on the same network.

Identity (`devices`) and address observations (`device_addresses`, `scan_results`) are stored separately, so IP history is kept.

---

## Quick start (development)

```bash
cd /home/nick/kali-netwatch
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[test]"            # or: pip install -r requirements.txt
export NETWATCH_CONFIG=config/netwatch.example.toml NETWATCH_DATA_DIR=$PWD/data
python -m app.cli init-db
printf 'a long admin passphrase\n' | python -m app.cli create-user admin --role admin --password-stdin
python -m app.cli doctor
python -m app.cli serve               # http://127.0.0.1:8787
pytest                                # 162 tests, no live network traffic
```

`python -m app.cli scan --profile quick` runs a real discovery scan of the configured networks in the foreground.
Do this only after you have confirmed the networks in your config are yours to scan.

---

## Installing on the Raspberry Pi

Requirements: Kali Linux ARM64, Python 3.11+, systemd, internet access for the first install (pip and apt).

```bash
cd /home/nick/kali-netwatch
sudo ./install.sh
```

The installer:
1. Checks the OS and architecture (warns if not Kali/Debian or not aarch64).
2. Checks Python, `nmap`, `iproute2` and `python3-venv`. Missing packages are listed and installed **only after you confirm**.
3. Creates the unprivileged system account `kalinetwatch` (no login shell).
4. Copies the code to `/opt/kali-netwatch` (the service cannot read `/home/nick`) and builds a venv there. The system Python is not changed.
5. Creates `/var/lib/kali-netwatch` (data), `/etc/kali-netwatch/netwatch.toml` and `netwatch.env`. Existing files are kept, and any replaced unit file is backed up first.
6. Initialises the database and prompts for the administrator username and password. The password is passed over stdin and never appears on a command line. There is no default password.
7. Installs and enables `kali-netwatch-web.service` and `kali-netwatch-scheduler.service`, which start at boot.
8. Prints service status and the dashboard address.

Dashboard: **http://127.0.0.1:8787** (localhost only by default). Run `sudo systemctl status kali-netwatch-*`.

Logs: `journalctl -u kali-netwatch-web -u kali-netwatch-scheduler -f`

Scan ranges are in `/etc/kali-netwatch/netwatch.toml`. The installer does not change network interfaces, firewall rules or routing.

---

## Configuration

Non-secret settings live in TOML (`config/netwatch.example.toml` is the template). Validation happens on startup; an invalid value stops the service with a clear error.

| Key | Default | Meaning |
|---|---|---|
| `app.data_dir` | `/var/lib/kali-netwatch` | Database, scan scratch files, lock file |
| `app.bind_host` | `127.0.0.1` | Must be an IP address. See *Exposing the dashboard* |
| `app.bind_port` | `8787` | Web port |
| `app.session_ttl_hours` | `12` | Session lifetime |
| `app.secure_cookies` | `false` | Set `true` when served over HTTPS |
| `app.history_retention_days` | `180` | Observations and events older than this are pruned daily |
| `networks.cidrs` | `192.168.50.0/24`, `192.168.1.0/24` | Seeded on first start; afterwards manage networks in the UI (Settings) |
| `scanning.privileged` | `false` | ARP/ICMP discovery. Requires `use_sudo = true` (see below) |
| `scanning.max_hosts_per_target` | `1024` | Upper bound for any custom target |
| `scanning.job_timeout_seconds` | `3600` | Hard limit for one scan job |
| `scanning.host_timeout_seconds` | `300` | Per-host nmap timeout |
| `scanning.max_parallelism` | `16` | Default nmap parallelism (1–64) |
| `scanning.nice_level` | `10` | CPU priority of nmap on the Pi |
| `scanning.top_ports` | `100` | Ports for standard and custom scans |
| `schedule.discovery_minutes` | `15` | Quick (host discovery) interval |
| `schedule.standard_hours` | `6` | Standard scan interval |
| `schedule.summary_hours` | `24` | Telegram summary interval |
| `change.offline_threshold` | `3` | Successful absent scans before a device is offline |
| `change.recent_days` | `7` | Recency window for identity matching |
| `telegram.enabled` | `false` | Master switch for Telegram |
| `telegram.cooldown_seconds` | `900` | Default cooldown when an alert rule sets none |

Alert rules (which event types notify, minimum severity, cooldown) are stored in the database and edited on the **Settings** page.

### Scan profiles

| Profile | Nmap arguments (summary) | Notes |
|---|---|---|
| Quick | `-sn -PS22,80,443,445,3389,8080 -PA80,443` | Discovery only. Does not touch ports |
| Standard | `-sT --top-ports 100 -sV --version-light` | Default for the 6-hourly scan |
| Detailed | `-sT -p <range> -sV --version-intensity 5`, host timeout doubled | Manual only; default range `1-1024` |
| Custom | Networks/targets, port spec, concurrency, host timeout, service detection | Manual only |

Every argument list is built in Python and run with `subprocess` as an argument array. No shell is used. The target is always placed after `--`. Port specs are numeric-only and limited to 50 entries and 10,000 ports. Targets must lie inside a configured network.

Only one scan job can be queued or running at a time. Manual requests get HTTP 409 when one is active. Scheduled jobs wait. An exclusive `flock` on `scan.lock` also guards against two runners.

### Privileged discovery (optional, read carefully)

Without root, nmap cannot send ARP or ICMP probes. Host discovery then uses TCP connect probes, which still find most devices. MAC addresses come from the kernel neighbour table, and only for subnets attached directly to the Pi.

For full ARP discovery, grant nmap root through sudo for the service account, then set `privileged = true` and `use_sudo = true`:

```
# /etc/sudoers.d/kali-netwatch   (install with visudo -cf before relying on it)
kalinetwatch ALL=(root) NOPASSWD: /usr/bin/nmap
```

**This rule lets the service account run any nmap option as root, and nmap can execute scripts.** Only enable it if you accept that risk. A future version should replace it with a validating wrapper. It is off by default.

---

## Telegram notifications

Secrets are read from the environment only. They are never stored in the database, the TOML file, logs, reports, or backups (by default).

1. In Telegram, talk to **@BotFather**, create a bot, and copy the token.
2. Send any message to your new bot, then find your chat ID (for example via `https://api.telegram.org/bot<TOKEN>/getUpdates`).
3. Edit the environment file, which is root-owned and readable by the service group:
   ```bash
   sudo nano /etc/kali-netwatch/netwatch.env
   # NETWATCH_TELEGRAM_BOT_TOKEN=123456:ABC...
   # NETWATCH_TELEGRAM_CHAT_ID=987654321
   ```
4. Set `enabled = true` under `[telegram]` in `/etc/kali-netwatch/netwatch.toml`, then `sudo systemctl restart kali-netwatch-web kali-netwatch-scheduler`.
5. Press **Send test message** on the Settings page. `app.cli doctor` also reports whether Telegram credentials are present.

Alerts follow the rules on the Settings page. Defaults:

| Event | Enabled | Minimum severity | Cooldown |
|---|---|---|---|
| New device | yes | low | none |
| Device offline | yes | medium | 30 min |
| Port opened (risky ports are medium) | yes | medium | 15 min |
| New finding | yes | high | 1 h |
| Scan failed | yes | high | 30 min |
| Application error | yes | high | 30 min |
| Daily summary | yes | info | - |

Cooldowns are enforced from `notification_history`, so they survive restarts. Telegram delivery failures are recorded and never stop scanning. Without credentials or with `enabled = false`, the application runs normally and sends nothing.

---

## Security model

- **Network exposure.** The server binds to `127.0.0.1` by default. Nothing is exposed to the LAN or internet unless you change this deliberately (see below).
- **Least privilege.** Both services run as `kalinetwatch`, a system account with no login shell. The systemd units set `NoNewPrivileges`, empty capability sets, `ProtectSystem=strict`, `ProtectHome`, a single writable path (`/var/lib/kali-netwatch`), memory limits and restricted address families.
- **Authentication.** There is no default password; the administrator is created during setup. Passwords are hashed with scrypt (N=2¹⁴, r=8, p=1) and a per-password salt. Comparisons are constant time. A dummy hash is verified for unknown users, so response time does not reveal usernames.
- **Sessions.** Random 256-bit tokens in `HttpOnly`, `SameSite=Strict` cookies (`Secure` when `secure_cookies = true`). Only the SHA-256 of the token is stored. Sessions expire and are revoked on logout, password reset and account disable.
- **CSRF.** Every state-changing request needs an `X-CSRF-Token` header matching the session's token. Login refuses cross-origin requests.
- **Authorisation.** Two roles, enforced on the server. `admin` can change things. `viewer` can read everything but cannot scan, edit or export audit logs.
- **Rate limiting.** Five failed logins from one client in 15 minutes lock that client out for 15 minutes (HTTP 429 with `Retry-After`).
- **Audit log.** Logins, failures, logouts, scan requests and cancellations, device edits, network changes, alert-rule changes and test messages are written to `audit_log` and shown on the Settings page.
- **Headers.** Content-Security-Policy restricts scripts and frames, plus `X-Frame-Options: DENY`, `nosniff` and `no-store` for API responses.
- **Input validation.** Pydantic models on every request body and query parameter. Networks, targets and ports are validated before they reach nmap. SQL is parameterised, and sort columns are whitelisted.
- **Secrets.** Telegram token and chat ID come from the environment only. Backups exclude `netwatch.env` unless you pass `--include-secrets`. Report exports never select password hashes or tokens (covered by tests).

---

## Exposing the dashboard

Keep the default `bind_host = "127.0.0.1"` until you need remote access. Recommended order:

1. **Preferred: an HTTPS reverse proxy on the Pi, with the app still on localhost.** Use Caddy or nginx on 443 and proxy to `127.0.0.1:8787`. Set `secure_cookies = true`. Example Caddyfile:
   ```
   netwatch.lan {
       tls internal
       reverse_proxy 127.0.0.1:8787
       header {
           Strict-Transport-Security "max-age=31536000"
       }
   }
   ```
   Do not expose the proxy to the internet. Forward only from your LAN, and keep the router's port-forwarding off. Make sure the proxy forwards the `Host` header unchanged, because the login CSRF check compares it with `Origin`.

2. **Direct LAN access (less safe, trusted LAN only).** Set `bind_host = "192.168.50.146"` (the Pi's own address, not `0.0.0.0`) and `secure_cookies = false` only while you use plain HTTP. Restart the web service. Any device on the LAN can then attempt logins, so use a strong passphrase and keep the rate limiter in mind.

Never expose the dashboard directly to the internet. The app does not implement TLS itself.

---

## Operations: upgrade, backup, recovery

| Task | Command |
|---|---|
| Health and configuration check | `sudo runuser -u kalinetwatch -- env PYTHONPATH=/opt/kali-netwatch NETWATCH_CONFIG=/etc/kali-netwatch/netwatch.toml /opt/kali-netwatch/.venv/bin/python -m app.cli doctor` |
| Back up (database + config, no secrets) | `sudo ./backup.sh` (writes `/var/backups/kali-netwatch/netwatch-backup-<time>.tar.gz` plus `.sha256`, mode 600) |
| Back up including secrets | `sudo ./backup.sh /path/to/dir --include-secrets` |
| Upgrade from a new source tree | Copy the updated sources into `/home/nick/kali-netwatch`, then `sudo ./update.sh` (backs up first, applies migrations, restarts, health-checks) |
| Restore | `sudo ./restore.sh ARCHIVE.tar.gz` (verifies the checksum and database integrity; stops services; keeps the previous DB as `netwatch.db.pre-restore-*`). Add `--restore-config` to restore the TOML file |
| Remove | `sudo ./uninstall.sh` (asks whether to keep data and configuration, and offers a final backup before deletion) |
| Apply retention now | `python -m app.cli prune` |
| Reset a password | `printf 'new passphrase\n' \| python -m app.cli reset-password admin --password-stdin` (also revokes all sessions) |
| Add a viewer | `printf 'pass\n' \| python -m app.cli create-user alice --role viewer --password-stdin` |

**Recovery after power loss.** SQLite in WAL mode with `synchronous=NORMAL` keeps committed transactions. Scans run in a single transaction per network, so an interrupted scan leaves either the previous state or the complete new one. On startup the scheduler marks jobs left `running` as `failed` ("interrupted"). The schedule is stored in the database, so it resumes without a catch-up storm.

**Recovery from a corrupt database.** Stop the services, run `restore.sh` with the latest good backup, then check the Events page for any gap. Rebuilding from scratch is also possible: removing the database and running `init-db` gives an empty inventory, and the next scans rebuild it.

---

## API

Browse to `/api/docs` (Swagger UI) or fetch `/api/openapi.json`.

| Group | Endpoints |
|---|---|
| Health | `GET /api/v1/health` (public), `GET /api/v1/system` (Pi metrics, interfaces, services) |
| Auth | `POST /api/v1/auth/login`, `POST /api/v1/auth/logout`, `GET /api/v1/auth/me` |
| Dashboard | `GET /api/v1/dashboard` |
| Devices | `GET /api/v1/devices` (filters: `q`, `network`, `vendor`, `device_type`, `status`, `risk`, `trusted`; `sort`, `order`, `page`, `size`), `GET /api/v1/devices/{id}`, `PATCH /api/v1/devices/{id}`, `GET /api/v1/devices/{id}/history` |
| Networks | `GET /api/v1/networks`, `POST /api/v1/networks`, `PATCH /api/v1/networks/{id}` |
| Scans | `GET /api/v1/scans`, `GET /api/v1/scans/{id}` (progress, log, per-network status), `POST /api/v1/scans`, `POST /api/v1/scans/{id}/cancel` |
| Security | `GET /api/v1/findings`, `POST /api/v1/findings/{id}/acknowledge`, `GET /api/v1/audit` |
| Events | `GET /api/v1/events` |
| Notifications | `GET /api/v1/notifications`, `POST /api/v1/notifications/test` |
| Settings | `GET /api/v1/settings`, `PUT /api/v1/settings/alert-rules` |
| Reports | `GET /api/v1/reports/{inventory|ports|findings|changes|statistics}/{csv|json|html}` |

Browser clients use the session cookie. Scripts can log in with `POST /auth/login`, keep the cookie, and send the returned `csrf_token` in `X-CSRF-Token` for state changes. Pagination is `page` and `size` (max 200).

---

## Vulnerability checks

Three checks, from safest to most intrusive. All are manual and admin-only, and none runs during a scan.

| Check | What it does | Sends data? | Default |
|---|---|---|---|
| **Known exploits (searchsploit)** | Looks up detected product and version in a local ExploitDB copy | No, nothing leaves the Pi | On when `exploitdb` is installed |
| **CVE check (vulners)** | Runs nmap's `vulners` script, which lists CVE IDs and CVSS scores for detected versions | **Yes: service names and versions go to vulners.com** | Off (`vulners_enabled = false`) |
| **Web exposure (Nuclei)** | Sends read-only HTTP requests to web ports using exposure, misconfiguration, technology and panel templates | **Yes: HTTP requests to your devices** | Off (`nuclei_enabled = false`) |

### Installing the tools (run these yourself)

```bash
sudo apt install exploitdb                      # searchsploit
sudo apt install nuclei                         # Nuclei; then:
nuclei -update-templates                        # downloads templates from the internet
# vulners script (only if you enable it):
sudo wget -O /usr/share/nmap/scripts/vulners.nse https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse
sudo nmap --script-updatedb
```

Check what NetWatch can see at **Findings → Check known exploits** or `GET /api/v1/vulnerability-tools`. The package and script names above are from memory of Kali's repositories and the vulners project. If `apt` cannot find `nuclei`, check the output and tell me.

### Enabling the online tools

In `/etc/kali-netwatch/netwatch.toml`, under `[vulnerability]`:

```toml
vulners_enabled = true   # service names/versions are sent to vulners.com
nuclei_enabled = true    # HTTP requests are sent to web ports on your devices
```

Restart the web and scheduler services after editing.

### What the results mean

- Every finding is labelled **unverified**. It says a tool reported something for the detected version, not that the device is exploitable.
- **Known exploits:** matches are medium severity. Many ExploitDB entries are for other platforms or old versions. Each run is limited to 200 lookups.
- **CVE check:** severity follows the highest CVSS score listed for that port (9.0+ critical, 7.0+ high, 4.0+ medium, else low). Patched backports can still be reported.
- **Web exposure:** templates run in low-rate mode (5 requests per second). Templates tagged `dos`, `fuzz`, `intrusive`, `brute-force`, `default-login`, and injection types are excluded. Out-of-band callbacks are disabled. Each match needs a manual look at the URL before you act on it.
- Runs refuse to start while a scan is queued or running, and only one check runs at a time. Progress is shown on the Findings page.

Nuclei and vulners only act on devices on your configured networks, and only on ports nmap already saw open. Scan one device first if you want to see the effect before running everything.

## Tests

```bash
. .venv/bin/activate && pytest
```

The suite (162 tests) uses realistic Nmap XML fixtures in `tests/fixtures/` and stubs the nmap process, so it never touches a live network. It covers database migrations and rollback, config validation, XML parsing, target and port validation with injection attempts, identity matching (including the cases that must not merge), change detection and offline thresholds, scan job lifecycle and overlap prevention, the executor (success, failure, timeout, cancel, partial), audit rules and scoring, authentication (hashing, sessions, CSRF, lockout), the full API through the real app factory, notifications (escaping, cooldowns, failure handling, token redaction), scheduler behaviour, retention, and backup/restore.

A live smoke run starts the server on a throwaway data directory, logs in, and requests every page and API endpoint without scanning anything.

---

## Project layout

```
app/
  main.py                 FastAPI factory, security headers, error redirects
  cli.py                  operator commands (doctor, create-user, scheduler, backup-db, ...)
  config.py               TOML loading and pydantic validation
  database/               WAL connections, transactions, forward-only migrations
  scanners/               target/port validation and nmap argument builders, runner,
                          XML parser, neighbour table and OUI helpers
  services/
    identity.py           device identity resolution
    ingest.py             persistence and change detection, one transaction per network
    audit.py              evidence-based findings and risk score
    jobs.py               queue, overlap prevention, cancellation, runner lock
    scan_executor.py      runs nmap per network and records per-network outcomes
    scheduler.py          persistent scheduler / runner process
    queries.py            read models for API and pages
    reports.py, health.py exports and Raspberry Pi metrics
    classify.py, bootstrap.py
  notifications/          Telegram client, formatting, cooldown-aware dispatcher
  security/auth.py        hashing, sessions, CSRF, rate limiting
  api/                    routes, auth endpoints, HTML pages, dependencies
  templates/, static/     Bootstrap UI and one vanilla-JS front end
migrations/001_initial.sql
config/netwatch.example.toml
systemd/                  hardened web and scheduler units
install.sh update.sh backup.sh restore.sh uninstall.sh   operations scripts (scripts/common.sh)
tests/                    pytest suite and fixtures
```

---

## Known limitations

- **Not yet run on the live network.** The application, the API, the pages and the test suite were verified here, but the installer and systemd units have not been executed on the Pi, and no scan has been run against 192.168.50.0/24 or 192.168.1.0/24. Running those is a deliberate next step.
- **Front-end assets come from a CDN** (Bootstrap 5.3.3, Chart.js 4.4.1 on jsDelivr). The dashboard needs internet access on the first load. Vendor these files into `app/static/` for an offline Pi. Subresource-integrity hashes are not included.
- **Unprivileged discovery is weaker.** Without root, nmap uses TCP connect probes, so hosts that drop those probes may be missed, and MACs appear only for directly attached subnets. Privileged mode needs the sudo rule described above.
- **Routed networks have no MAC addresses** on the Pi. Devices there are identified by IP, hostname and vendor fallback, which makes identity less certain.
- **SMBv1 detection** depends on NSE output. Default scans do not run scripts, so the rule only fires if script output is present. It is not invented from banners.
- **"Unexpected externally reachable services"** are not checked. That requires a vantage point outside your network.
- **Scan progress** shows the unit (network or target) and completion, not a live percentage from nmap.
- **Closed-port detection** is conservative: a port is reported closed only when the current scan covered it.
- **Single-node design.** There is one web worker and one scheduler, and the rate limiter is in memory. Both are fine for a Pi, but they are not horizontally scalable.
- **No user-management UI.** Users are managed from the command line.
- **Timers are not used.** The scheduler is a persistent process; systemd timers were considered and rejected for the reasons in `systemd/README.txt`.
- **Retention deletes history** older than `history_retention_days`. Current device and finding state is never deleted.

## Recommended next steps

1. Run `sudo ./install.sh` on the Pi, check `app.cli doctor`, then run one **quick** scan of each network.
2. Review the discovered inventory. Name devices, set types and trust the ones you know, and check each finding's evidence before acting on it.
3. Configure Telegram and confirm a test message arrives.
4. Schedule a backup (`sudo ./backup.sh`) with a cron job or systemd timer.
5. Vendor the CDN assets and add a validating wrapper for privileged nmap if you need ARP discovery.
