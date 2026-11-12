"""Long-running scheduler/runner process (systemd unit: kali-netwatch-scheduler).

Responsibilities:
  * enqueue scheduled scans (quick = host discovery, standard = common ports)
  * execute queued jobs, one at a time, under an exclusive lock
  * dispatch notifications for new events
  * daily Telegram summary and retention pruning
  * write a heartbeat so the web UI can show scheduler health

The web process only enqueues manual scans; it never runs nmap itself.
"""
from __future__ import annotations

import logging
import signal
import time
from datetime import datetime, timedelta, timezone

from app.config import Settings
from app.database import init_database
from app.database.connection import transaction, utc_now
from app.notifications import dispatcher, telegram
from app.scanners.targets import ScanRequest
from app.security.auth import purge_expired_sessions, safe_error_text
from app.services import jobs
from app.services.bootstrap import get_setting, seed_defaults, set_setting
from app.services.scan_executor import execute_job

log = logging.getLogger("netwatch.scheduler")
TICK_SECONDS = 2.0


class Scheduler:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.conn = init_database(settings.db_path)
        seed_defaults(self.conn, settings)
        self._stop = False

    # ----- lifecycle -------------------------------------------------------
    def request_stop(self, *_: object) -> None:
        self._stop = True

    def run_forever(self) -> None:
        signal.signal(signal.SIGTERM, self.request_stop)
        signal.signal(signal.SIGINT, self.request_stop)
        recovered = jobs.recover_interrupted(self.conn)
        if recovered:
            log.warning("marked %d interrupted scan job(s) as failed", recovered)
        log.info("scheduler started (db=%s)", self.settings.db_path)
        backoff = 0.0
        while not self._stop:
            try:
                self.tick()
                backoff = 0.0
            except Exception as exc:  # keep the service alive; report the failure
                backoff = min(300.0, max(5.0, backoff * 2))
                log.exception("scheduler tick failed")
                self._report_app_error(exc)
                time.sleep(backoff)
            time.sleep(TICK_SECONDS)
        log.info("scheduler stopped")

    # ----- one iteration ---------------------------------------------------
    def tick(self) -> None:
        set_setting(self.conn, "scheduler_heartbeat", utc_now())
        self.enqueue_due()
        from app.services.jobs import runner_lock
        with runner_lock(self.settings.scan_lock_path) as acquired:
            if acquired:
                job = jobs.claim_next(self.conn)
                if job is not None:
                    log.info("running job %s (%s)", job["id"], job["profile"])
                    status = execute_job(self.conn, self.settings, job)
                    log.info("job %s finished: %s", job["id"], status)
        dispatcher.dispatch_pending(self.conn, self.settings)
        self.daily_tasks()

    def enqueue_due(self) -> None:
        sched = self.settings.schedule
        if not sched.enabled:
            return
        due = [
            ("quick", timedelta(minutes=sched.discovery_minutes)),
            ("standard", timedelta(hours=sched.standard_hours)),
        ]
        for profile, interval in due:
            key = f"sched_last:{profile}"
            last = get_setting(self.conn, key, "")
            if last and datetime.now(timezone.utc) - _ts(last) < interval:
                continue
            if jobs.active_job(self.conn) is not None:
                continue  # never overlap; retry on the next tick
            networks = [r["cidr"] for r in self.conn.execute(
                "SELECT cidr FROM networks WHERE enabled = 1 ORDER BY cidr")]
            if not networks:
                continue
            req = ScanRequest(profile=profile, networks=tuple(networks))
            jobs.create_job(self.conn, req, trigger="schedule", requested_by="scheduler")
            set_setting(self.conn, key, utc_now())

    def daily_tasks(self) -> None:
        if self._due("sched_last:summary", timedelta(hours=self.settings.schedule.summary_hours)):
            if self.settings.telegram.enabled and self.settings.telegram.daily_summary:
                from app.services.queries import summary_stats
                text = telegram.format_summary(summary_stats(self.conn))
                try:
                    telegram.send(text)
                    dispatcher._record(self.conn, "daily_summary", "daily_summary", "sent", "daily summary")
                except telegram.TelegramError as exc:
                    dispatcher._record(self.conn, "daily_summary", "daily_summary", "failed",
                                       "daily summary", str(exc))
            set_setting(self.conn, "sched_last:summary", utc_now())
        if self._due("sched_last:maintenance", timedelta(hours=24)):
            self.prune_history()
            purge_expired_sessions(self.conn)
            set_setting(self.conn, "sched_last:maintenance", utc_now())

    def prune_history(self) -> dict:
        """Delete observations older than the retention window. Never runs during scans."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=self.settings.app.history_retention_days))
        stamp = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")
        removed = {}
        with transaction(self.conn):
            for table, col in (("device_observations", "observed_at"), ("service_observations", "observed_at"),
                               ("notification_history", "created_at"), ("events", "created_at"),
                               ("audit_log", "created_at")):
                removed[table] = self.conn.execute(f"DELETE FROM {table} WHERE {col} < ?", (stamp,)).rowcount
            removed["scan_results"] = self.conn.execute(
                "DELETE FROM scan_results WHERE observed_at < ?", (stamp,)).rowcount
        log.info("retention pruned: %s", removed)
        return removed

    # ----- helpers ---------------------------------------------------------
    def _due(self, key: str, interval: timedelta) -> bool:
        last = get_setting(self.conn, key, "")
        return not last or datetime.now(timezone.utc) - _ts(last) >= interval

    def _report_app_error(self, exc: BaseException) -> None:
        try:
            from app.services.ingest import _store_events
            with transaction(self.conn):
                _store_events(self.conn, [{"type": "app_error", "severity": "high",
                                           "title": f"Scheduler error: {safe_error_text(exc)}",
                                           "device_id": None, "job_id": None, "details": {}}], utc_now())
        except Exception:  # pragma: no cover - last-resort guard
            log.error("could not record app_error event")


def _ts(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
