"""WZML Heroku RAM watchdog (stdlib-only).

Install as bot/helper/ext_utils/ram_watchdog.py; call start_ram_watchdog()
exactly once from bot/__main__.py.

Uses cgroup memory.current/usage_in_bytes when visible. Otherwise reports
an *estimate* of memory used by visible processes, sampled from /proc.
Process RSS sums shared pages and does not equal Heroku dyno total memory.
A less frequent PSS sample is diagnostic only.

By default the watchdog DOES NOT kill a dyno based on /proc estimates.
Keep RAM_WATCHDOG_DRY_RUN=true until actual readings have been compared with
Heroku runtime metrics. The dyno will lose active tasks on a forced exit.
"""
import importlib
import logging
import os
import re
import threading
import time
from pathlib import Path

logger = logging.getLogger(__name__)
_MIB = 1024 * 1024
_lock = threading.Lock()
_started = False

_DEFAULTS = {
    "RAM_WATCHDOG_ENABLED": True,
    "RAM_WARN_MB": 1000,
    "RAM_RESTART_MB": 1100,
    "RAM_CHECK_SECONDS": 3,
    "RAM_CONFIRM_SAMPLES": 20,
    "RAM_STARTUP_GRACE_SECONDS": 120,
    "RAM_WATCHDOG_DRY_RUN": True,
    "RAM_ALLOW_PROC_RESTART": False,
    "RAM_PSS_SAMPLE_SECONDS": 60,
}


def _settings():
    """Environment overrides config.py; report source to help debugging.

    Importing config.py also executes any mapping in that file. No change to
    WZML's separate database-backed settings manager is required.
    """
    config = None
    try:
        config = importlib.import_module("config")
    except ImportError as exc:
        # Ignore only a missing top-level config module; surface broken imports.
        if exc.name != "config":
            raise
        logger.warning("[RAM WATCHDOG] config.py not importable; using environment/defaults")
    values, sources = {}, {}
    for name, default in _DEFAULTS.items():
        if name in os.environ:
            values[name] = os.environ[name]
            sources[name] = "environment"
        elif config is not None and hasattr(config, name):
            values[name] = getattr(config, name)
            sources[name] = "config.py"
        else:
            values[name] = default
            sources[name] = "default"
    def parse_bool(v):
        if isinstance(v, bool):
            return v
        s = str(v).strip().lower()
        if s not in ("true", "false", "1", "0", "yes", "no", "on", "off"):
            raise ValueError(f"Invalid boolean watchdog setting: {v!r}")
        return s in ("true", "1", "yes", "on")
    for name in ("RAM_WATCHDOG_ENABLED", "RAM_WATCHDOG_DRY_RUN", "RAM_ALLOW_PROC_RESTART"):
        values[name] = parse_bool(values[name])
    for name in ("RAM_WARN_MB", "RAM_RESTART_MB", "RAM_CHECK_SECONDS", "RAM_STARTUP_GRACE_SECONDS", "RAM_PSS_SAMPLE_SECONDS"):
        values[name] = float(values[name])
    values["RAM_CONFIRM_SAMPLES"] = int(values["RAM_CONFIRM_SAMPLES"])
    if values["RAM_CHECK_SECONDS"] < 1 or values["RAM_CONFIRM_SAMPLES"] < 1:
        raise ValueError("Check interval and confirmation samples must be positive")
    if values["RAM_WARN_MB"] <= 0 or values["RAM_RESTART_MB"] <= 0:
        raise ValueError("RAM thresholds must be positive")
    if values["RAM_PSS_SAMPLE_SECONDS"] < 15 or values["RAM_STARTUP_GRACE_SECONDS"] < 0:
        raise ValueError("Invalid PSS interval or startup grace")
    return values, sources


def _read_int(path):
    try:
        value = Path(path).read_text(encoding="utf-8").strip()
        return int(value) if value.isdigit() else None
    except (OSError, ValueError):
        return None


def _unescape_mount(value):
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), value)


def _cgroup_paths():
    membership = {}
    try:
        for line in Path("/proc/self/cgroup").read_text().splitlines():
            parts = line.split(":", 2)
            if len(parts) == 3:
                _, ctrls, loc = parts
                if not ctrls:
                    membership["v2"] = loc
                elif "memory" in ctrls.split(","):
                    membership["v1"] = loc
    except OSError:
        pass
    paths = []
    try:
        lines = Path("/proc/self/mountinfo").read_text().splitlines()
    except OSError:
        lines = []
    for line in lines:
        left, sep, right = line.partition(" - ")
        if not sep:
            continue
        l, r = left.split(), right.split()
        if len(l) < 5 or len(r) < 3:
            continue
        kind = "v2" if r[0] == "cgroup2" else "v1" if r[0] == "cgroup" and "memory" in (r[1] + "," + r[2]).split(",") else None
        if kind not in membership:
            continue
        root = os.path.normpath(_unescape_mount(l[3]))
        current = os.path.normpath(membership[kind])
        if current == root:
            rel = ""
        elif root == "/":
            rel = current.lstrip("/")
        elif current.startswith(root + "/"):
            rel = current[len(root)+1:]
        else:
            continue
        filename = "memory.current" if kind == "v2" else "memory.usage_in_bytes"
        paths.append(Path(_unescape_mount(l[4])) / rel / filename)
    if "v2" in membership:
        paths.append(Path("/sys/fs/cgroup/memory.current"))
    if "v1" in membership:
        paths.append(Path("/sys/fs/cgroup/memory/memory.usage_in_bytes"))
    return list(dict.fromkeys(paths))


def _proc_rss():
    """Fast process RSS sum (potentially double-counts shared memory)."""
    total, counted, skipped = 0, 0, 0
    try:
        entries = list(Path("/proc").iterdir())
    except OSError:
        return None
    page_size = os.sysconf("SC_PAGE_SIZE")
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            # Exclude kernel threads; process visibility may differ by dyno.
            if not (entry / "cmdline").read_bytes().strip(b"\x00"):
                continue
            fields = (entry / "statm").read_text().split()
            total += int(fields[1]) * page_size
            counted += 1
        except (OSError, ValueError, IndexError):
            skipped += 1
    if counted == 0:
        return None
    return (total / _MIB, counted, skipped)


def _proc_pss():
    """Slower diagnostic PSS sum; do not use for restart decisions."""
    total, counted, skipped = 0, 0, 0
    try:
        entries = list(Path("/proc").iterdir())
    except OSError:
        return None
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            if not (entry / "cmdline").read_bytes().strip(b"\x00"):
                continue
            with (entry / "smaps_rollup").open(encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if line.startswith("Pss:"):
                        total += int(line.split()[1]) * 1024
                        counted += 1
                        break
        except (OSError, ValueError, IndexError):
            skipped += 1
    if counted == 0:
        return None
    return (total / _MIB, counted, skipped)


def memory_measurement():
    """Return (MB, source, detail) or (None, 'unavailable', '')."""
    for path in _cgroup_paths():
        used = _read_int(path)
        if used is not None:
            return (used / _MIB, "cgroup", str(path))
    rss = _proc_rss()
    if rss is not None:
        used, counted, skipped = rss
        return (used, "proc-rss-estimate", f"processes={counted} unreadable={skipped}")
    return (None, "unavailable", "")


def _worker(settings):
    warn = settings["RAM_WARN_MB"]
    restart = settings["RAM_RESTART_MB"]
    interval = settings["RAM_CHECK_SECONDS"]
    confirm = settings["RAM_CONFIRM_SAMPLES"]
    grace = settings["RAM_STARTUP_GRACE_SECONDS"]
    dry_run = settings["RAM_WATCHDOG_DRY_RUN"]
    allow_proc = settings["RAM_ALLOW_PROC_RESTART"]
    pss_interval = settings["RAM_PSS_SAMPLE_SECONDS"]
    last_report = -float("inf")
    last_pss = -float("inf")
    last_alert = -float("inf")
    start = time.monotonic()
    consecutive = 0
    prev_source = None
    warned = False
    while True:
        now = time.monotonic()
        try:
            used, source, detail = memory_measurement()
            if source != prev_source:
                logger.warning("[RAM WATCHDOG] memory source=%s %s", source, detail)
                prev_source = source
            if now - last_report >= 60:
                if used is None:
                    logger.warning("[RAM WATCHDOG] memory metric unavailable; restart disabled")
                else:
                    logger.info("[RAM WATCHDOG] %.1f MB source=%s %s", used, source, detail)
                last_report = now
            if source == "proc-rss-estimate" and now - last_pss >= pss_interval:
                pss = _proc_pss()
                if pss is not None:
                    logger.info("[RAM WATCHDOG] diagnostic PSS=%.1f MB processes=%d unreadable=%d (not restart metric)", *pss)
                last_pss = now
            if used is None:
                consecutive = 0
                warned = False
            else:
                if used >= warn and not warned:
                    logger.warning("[RAM WATCHDOG] high RAM: %.1f MB source=%s", used, source)
                    warned = True
                elif used < warn:
                    warned = False
                if used < restart or now - start < grace:
                    consecutive = 0
                else:
                    consecutive += 1
                    if consecutive >= confirm and now - last_alert >= 60:
                        permitted = source == "cgroup" or (source == "proc-rss-estimate" and allow_proc)
                        if dry_run or not permitted:
                            logger.warning("[RAM WATCHDOG] %.1f MB >= %.0f MB for %d samples; %s", used, restart, consecutive,
                                           "DRY-RUN: would exit" if dry_run else "NO RESTART: process estimate not approved")
                            last_alert = now
                        else:
                            logger.critical("[RAM WATCHDOG] sustained RAM threshold hit (%.1f MB >= %.0f MB); exiting", used, restart)
                            logging.shutdown()
                            os._exit(1)
        except Exception:
            consecutive = 0
            logger.exception("[RAM WATCHDOG] monitoring error (no restart)")
        time.sleep(interval)


def start_ram_watchdog():
    """Start once; safe to call from module initialization."""
    global _started
    with _lock:
        if _started:
            return
        try:
            settings, sources = _settings()
        except Exception:
            logger.exception("[RAM WATCHDOG] configuration invalid; watchdog not started")
            return
        if not settings["RAM_WATCHDOG_ENABLED"]:
            logger.info("[RAM WATCHDOG] disabled")
            return
        _started = True
        logger.info("[RAM WATCHDOG] settings: warn=%.0f restart=%.0f interval=%.1fs confirm=%d grace=%.0fs dry_run=%s allow_proc_restart=%s",
                    settings["RAM_WARN_MB"], settings["RAM_RESTART_MB"], settings["RAM_CHECK_SECONDS"],
                    settings["RAM_CONFIRM_SAMPLES"], settings["RAM_STARTUP_GRACE_SECONDS"],
                    settings["RAM_WATCHDOG_DRY_RUN"], settings["RAM_ALLOW_PROC_RESTART"])
        logger.info("[RAM WATCHDOG] config sources: %s", ", ".join(f"{k}={v}" for k, v in sources.items()))
        if settings["RAM_RESTART_MB"] <= settings["RAM_WARN_MB"]:
            logger.warning("[RAM WATCHDOG] restart threshold should exceed warning threshold")
        threading.Thread(target=_worker, args=(settings,), daemon=True, name="ram-watchdog").start()
        logger.info("[RAM WATCHDOG] started")
