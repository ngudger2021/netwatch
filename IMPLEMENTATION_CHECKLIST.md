# Kali NetWatch: implementation checklist

Read this first if you are picking the project up. Update it as each item changes.
Status key: [x] done and tested, [~] in progress, [ ] not started, [!] blocked (see note).

## Project baseline (done)
- [x] Core app: config, SQLite WAL + migrations, nmap runner/parser, identity, change detection
- [x] Audit rules and risk score (non-intrusive, evidence based)
- [x] Scheduler, scan queue with overlap protection and cancellation
- [x] Web UI (dashboard, inventory, device pages, scans, findings, events, reports, settings, system)
- [x] Telegram alerts with cooldowns
- [x] install / update / backup / restore / uninstall scripts; hardened systemd units
- [x] Installed and running on the Pi (bind address is localhost unless changed in netwatch.toml)
- [x] Git repo prepared, remote https://github.com/ngudger2021/netwatch.git (NOT pushed)
- [x] Fixed: migrations path in installed copy; PYTHONPATH for service account; --unprivileged for nmap; chart resize loop

## Vulnerability checks (current work)
Decisions taken: manual-only; no exploitation; findings are version-based and labelled "unverified".
- [x] Tool detection endpoint: GET /api/v1/vulnerability-tools (is searchsploit installed?)
- [x] Query builder: product + version, strictly sanitised, length-limited (app/services/vuln_lookup.py)
- [x] Searchsploit runner: argv only, timeout, JSON parse, CVE extraction from "Codes"
  - [ ] VERIFY on the Pi after `apt install exploitdb`: confirm `searchsploit --json` output matches the fixture (tests use a fixture, not the real tool)
- [x] Persist as findings (rule key exploitdb_match, severity medium, weight 5, unverified)
- [x] Audit sync must NOT auto-resolve exploitdb_match findings (sync_device_findings only resolves built-in rules)
- [x] API: POST /api/v1/vulnerability-checks (admin, CSRF) for one device or all devices, capped count
- [x] UI: "Check known exploits" button on Findings page (admin). Device page button not added yet
- [x] Tests: parser with fixture JSON, sanitiser rejects shell metacharacters, sync keeps exploitdb findings, endpoint with fake tool (tests/test_vuln_lookup.py)
- [x] Docs: README section (Known-exploit checks)
- [ ] Telegram/alert for exploitdb findings: currently no finding_new event is raised by the lookup (decide)

## Vulners + Nuclei (current work, approved by user "get this working")
Decisions: both OFF by default in netwatch.toml ([vulnerability]); vulners sends banners to vulners.com (user must opt in);
Nuclei restricted to exposure/misconfig/tech/panel templates, excludes dos/fuzz/intrusive/brute-force/default-login, low rate.
Runs are manual, in a background thread, one at a time, refused while a scan is running.
- [x] Config: [vulnerability] section (vulners_enabled, nuclei_enabled, nuclei_templates_dir, limits); both off by default
- [x] vulners: nmap argv (-sT -sV --script vulners -p ... ) with validated IP + ports; output parser (CVE + CVSS)
- [x] vulners findings: rule vulners_cve, severity by CVSS, unverified label
- [x] nuclei: target URLs from open web ports only; argv with fixed safe flags; JSONL parser; exact host+port matching (fixed prefix bug found in review)
- [x] nuclei findings: rule nuclei_match per port
- [x] Background runner with status in app_settings, lock, refuses during scans (app/services/vuln_runner.py)
- [x] API: GET /api/v1/vulnerability-tools, GET /api/v1/vulnerability-checks/status, POST /api/v1/vulnerability-checks with tools list
- [x] Findings page: tool buttons (disabled when off or not installed) + progress polling
- [x] Tests with fake nmap XML containing vulners output and fake nuclei JSONL (tests/test_vuln_scan.py)
- [ ] Verify on Pi after installing: `nuclei -version`, `nmap --script-help vulners` (package names in README are unverified)

## Not started / awaiting your decision
- [!] Install exploitdb on the Pi: `sudo apt install exploitdb` (system change; run it yourself)
- [x] `vulners` NSE script built (install step is the user's; see README)
- [x] Nuclei template scan built (install step is the user's; see README)
- [ ] Two-factor login for NetWatch (not requested yet)
- [ ] Vendor CDN assets for offline use

## Verification log
- 2026-11-12: 168 tests passing before vulnerability work started
- 2026-11-12: 185 tests passing after vulnerability lookup (searchsploit) added. Not yet run on the Pi (needs exploitdb installed)
- 2026-11-12: 206 tests passing after vulners + Nuclei added (incl. background run success and lock-refusal tests). Not yet run on the Pi
- Found and fixed during this work: late-bound search function default (tests caught it); audit sync would have wiped non-builtin findings
