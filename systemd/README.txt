Units installed by install.sh into /etc/systemd/system:
  kali-netwatch-web.service        web UI and JSON API on 127.0.0.1:8787
  kali-netwatch-scheduler.service  scheduled discovery, standard scans, scan execution, notifications

Scheduling uses an in-process scheduler whose state is stored in SQLite, so the
schedule survives reboots. This was chosen over systemd timers so that scans can
be queued from the web UI, cancelled, and serialised through one lock.
