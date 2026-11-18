"""Optional in-process RAM watchdog for a Heroku Python dyno.

Reads Linux cgroup memory accounting (v2 or v1), not only the Python RSS.
Disable with RAM_WATCHDOG_ENABLED=false.
"""
import logging
import os
import threading
import time
from pathlib import Path

logger = logging.getLogger(__name__)
_started = False
_lock = threading.Lock()


def _read_int(path):
    try:
        value = Path(path).read_text().strip()
        if value != 'max':
            return int(value)
    except (OSError, ValueError):
        pass
    return None


def _cgroup_paths():
    """Find current cgroup membership (handles nested paths where accessible)."""
    try:
        memberships = Path('/proc/self/cgroup').read_text().splitlines()
    except OSError:
        return []
    v2_path = None
    v1_path = None
    for line in memberships:
        parts = line.split(':', 2)
        if len(parts) != 3:
            continue
        _, controllers, relative = parts
        if not controllers:
            v2_path = relative.lstrip('/')
        if 'memory' in controllers.split(','):
            v1_path = relative.lstrip('/')
    paths = []
    if v2_path is not None:
        paths.extend([Path('/sys/fs/cgroup') / v2_path / 'memory.current', Path('/sys/fs/cgroup/memory.current')])
    if v1_path is not None:
        paths.extend([Path('/sys/fs/cgroup/memory') / v1_path / 'memory.usage_in_bytes', Path('/sys/fs/cgroup/memory/memory.usage_in_bytes')])
    return list(dict.fromkeys(paths))


def memory_mb():
    for path in _cgroup_paths():
        count = _read_int(path)
        if count is not None:
            return count / 1024 / 1024
    return None


def _worker():
    warn_mb = float(os.getenv('RAM_WARN_MB', '750'))
    restart_mb = float(os.getenv('RAM_RESTART_MB', '850'))
    interval = max(1.0, float(os.getenv('RAM_CHECK_SECONDS', '2')))
    consecutive_needed = max(1, int(os.getenv('RAM_CONFIRM_SAMPLES', '2')))
    grace_seconds = max(0.0, float(os.getenv('RAM_STARTUP_GRACE_SECONDS', '120')))
    dry_run = os.getenv('RAM_WATCHDOG_DRY_RUN', 'true').lower() in ('true', '1', 'yes')
    start = time.monotonic()
    hits = 0
    warned = False
    last_report = 0.0
    while True:
        try:
            used = memory_mb()
            now = time.monotonic()
            if used is None:
                if now - last_report >= 60:
                    logger.warning('[RAM WATCHDOG] cgroup memory metric unavailable; no restart action')
                    last_report = now
                time.sleep(interval)
                continue
            if now - last_report >= 60:
                logger.info('[RAM WATCHDOG] dyno memory %.0f MB', used)
                last_report = now
            if used >= warn_mb and not warned:
                logger.warning('[RAM WATCHDOG] high memory: %.0f MB (warning %.0f MB)', used, warn_mb)
                warned = True
            elif used < warn_mb:
                warned = False
            if used >= restart_mb:
                hits += 1
                if hits >= consecutive_needed and now - start >= grace_seconds:
                    logger.error('[RAM WATCHDOG] %.0f MB >= %.0f MB; %s', used, restart_mb, 'DRY-RUN: would exit' if dry_run else 'exiting dyno process')
                    if not dry_run:
                        # Heroku can restart its dyno after the process exits.
                        # This is an emergency stop, not a graceful task shutdown.
                        logging.shutdown()
                        os._exit(1)
                    hits = 0
            else:
                hits = 0
        except Exception:
            logger.exception('[RAM WATCHDOG] check failed; continuing')
        time.sleep(interval)


def start_ram_watchdog():
    global _started
    if os.getenv('RAM_WATCHDOG_ENABLED', 'true').lower() in ('false', '0', 'no'):
        return
    with _lock:
        if _started:
            return
        _started = True
        thread = threading.Thread(target=_worker, name='ram-watchdog', daemon=True)
        thread.start()
        logger.info('[RAM WATCHDOG] started')
