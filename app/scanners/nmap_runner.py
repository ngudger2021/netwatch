"""Runs nmap as a subprocess with an argument array (never a shell string).

Supports a hard timeout, cooperative cancellation, lowered CPU priority and
optional sudo for privileged discovery. stdout/stderr are sent to files so a
chatty process can never block on a full pipe.
"""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass
from typing import Callable

from app.config import ScanningConfig


@dataclass
class RunResult:
    returncode: int | None
    timed_out: bool
    cancelled: bool
    stderr_tail: str
    elapsed: float

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.cancelled


class NmapUnavailable(RuntimeError):
    pass


def build_command(cfg: ScanningConfig, nmap_args: list[str]) -> list[str]:
    nmap = cfg.nmap_path
    if not os.path.isfile(nmap):
        found = shutil.which("nmap")
        if not found:
            raise NmapUnavailable("nmap is not installed (sudo apt install nmap)")
        nmap = found
    cmd: list[str] = []
    if cfg.use_sudo:
        cmd += ["sudo", "-n", "--"]
    nice = shutil.which("nice")
    if nice and cfg.nice_level:
        cmd += [nice, "-n", str(cfg.nice_level)]
    cmd += [nmap, *nmap_args]
    return cmd


def run_command(
    cmd: list[str],
    *,
    timeout: float,
    stderr_path: str,
    should_cancel: Callable[[], bool] = lambda: False,
    poll_interval: float = 0.5,
) -> RunResult:
    """Execute cmd, killing its process group on timeout or cancellation."""
    start = time.monotonic()
    with open(stderr_path, "wb") as err:
        proc = subprocess.Popen(
            cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=err,
            start_new_session=True, shell=False, close_fds=True,
        )
        timed_out = cancelled = False
        while True:
            try:
                proc.wait(timeout=poll_interval)
                break
            except subprocess.TimeoutExpired:
                if should_cancel():
                    cancelled = True
                elif time.monotonic() - start > timeout:
                    timed_out = True
                if cancelled or timed_out:
                    _kill_group(proc)
                    break
    tail = ""
    try:
        with open(stderr_path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - 2000))
            tail = fh.read().decode("utf-8", "replace")
    except OSError:
        pass
    return RunResult(proc.returncode, timed_out, cancelled, tail, time.monotonic() - start)


def _kill_group(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        proc.wait()
