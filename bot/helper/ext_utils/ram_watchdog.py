"""Heroku/WZML internal RAM watchdog.

Install at bot/helper/ext_utils/ram_watchdog.py and call
start_ram_watchdog() once from bot/__main__.py.

Reads memory from Linux cgroups (v2 or v1), including child processes and
accounted cache. If the container does not expose a usable memory metric, it
logs diagnostics and NEVER restarts the dyno on an unverified measurement.

Configuration uses RAM_* environment variables. A config.py that defines
Python variables must export them to os.environ before starting this module.
"""

import logging
import os
import re
import threading
import time
from pathlib import Path

logger = logging.getLogger(__name__)
_started = False
_lock = threading.Lock()
_debug_logged = False


def _env_bool(name, default):
    return os.getenv(name, str(default)).strip().lower() in ("true", "1", "yes", "on")


def _read_int(path):
    try:
        raw = Path(path).read_text(encoding="utf-8").strip()
        if raw != "max":
            value = int(raw)
            return value if value >= 0 else None
    except (OSError, ValueError):
        pass
    return None


def _unescape_mount(text):
    """Decode mountinfo's octal-escaped spaces, tabs, backslashes, etc."""
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), text)


def _memberships():
    result = {}
    try:
        lines = Path("/proc/self/cgroup").read_text(encoding="utf-8").splitlines()
    except OSError:
        return result
    for line in lines:
        parts = line.split(":", 2)
        if len(parts) != 3:
            continue
        _, controllers, cgroup_path = parts
        if controllers == "":
            result["v2"] = cgroup_path
        elif "memory" in controllers.split(","):
            result["v1"] = cgroup_path
    return result


def _mounts():
    """Return memory-cgroup mounts as (version, mount_root, mount_point)."""
    mounts = []
    try:
        lines = Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
    except OSError:
        return mounts
    for line in lines:
        left, separator, right = line.partition(" - ")
        if not separator:
            continue
        before, after = left.split(), right.split()
        if len(before) < 5 or len(after) < 3:
            continue
        fstype, source, super_options = after[:3]
        root = _unescape_mount(before[3])
        point = _unescape_mount(before[4])
        if fstype == "cgroup2":
            mounts.append(("v2", root, point))
        elif fstype == "cgroup":
            options = set(before[5].split(",") if len(before) > 5 else [])
            options.update(super_options.split(","))
            options.update(source.split(","))
            if "memory" in options:
                mounts.append(("v1", root, point))
    return mounts


def _relative_to_mount(cgroup_path, mount_root):
    """Find a membership's directory relative to a cgroup filesystem mount."""
    cg = "/" + cgroup_path.lstrip("/")
    root = "/" + mount_root.lstrip("/")
    cg = os.path.normpath(cg)
    root = os.path.normpath(root)
    if cg == root:
        return ""
    if root == "/":
        return cg.lstrip("/")
    if cg.startswith(root + "/"):
        return cg[len(root) + 1:]
    # A namespace mismatch: do not blindly read an unrelated parent's cgroup.
    return None


def _cgroup_paths():
    members = _memberships()
    candidates = []
    filenames = {"v2": "memory.current", "v1": "memory.usage_in_bytes"}
    for version, mount_root, mount_point in _mounts():
        if version not in members:
            continue
        relative = _relative_to_mount(members[version], mount_root)
        if relative is None:
            continue
        candidates.append(Path(mount_point) / relative / filenames[version])

    # Conventional paths can help when mountinfo is restricted or unusual.
    # Only attempt paths for a cgroup version reported by /proc/self/cgroup.
    if "v2" in members:
        candidates.append(Path("/sys/fs/cgroup/memory.current"))
    if "v1" in members:
        candidates.append(Path("/sys/fs/cgroup/memory/memory.usage_in_bytes"))
        candidates.append(Path("/sys/fs/cgroup/memory.usage_in_bytes"))
    return list(dict.fromkeys(candidates))


def _diagnose(paths):
    global _debug_logged

    # Run diagnostics only once to avoid flooding Heroku logs
    if _debug_logged:
        return

    _debug_logged = True

    logger.warning(
        "[RAM WATCHDOG] No readable cgroup memory metric; "
        "restart protection inactive"
    )

    # 1. Show candidate memory paths
    logger.warning(
        "[RAM DEBUG] Candidate files: %s",
        [str(path) for path in paths]
    )

    # 2. Check candidate files
    for path in paths:
        try:
            p = Path(path)

            logger.warning(
                "[RAM DEBUG] File: %s | exists=%s | readable=%s",
                path,
                p.exists(),
                os.access(path, os.R_OK),
            )

            if p.exists():
                try:
                    content = p.read_text(
                        encoding="utf-8"
                    ).strip()

                    logger.warning(
                        "[RAM DEBUG] File content: %s",
                        content[:500]
                    )

                except Exception as exc:
                    logger.warning(
                        "[RAM DEBUG] Cannot read %s: %s",
                        path,
                        exc
                    )

        except Exception as exc:
            logger.warning(
                "[RAM DEBUG] File inspection failed: %s",
                exc
            )

    # 3. Check cgroup membership
    try:
        content = Path(
            "/proc/self/cgroup"
        ).read_text(encoding="utf-8")

        logger.warning(
            "[RAM DEBUG] /proc/self/cgroup:\n%s",
            content[:3000]
        )

    except Exception as exc:
        logger.warning(
            "[RAM DEBUG] Cannot read cgroup membership: %s",
            exc
        )

    # 4. Inspect all mount information
    try:
        lines = Path(
            "/proc/self/mountinfo"
        ).read_text(
            encoding="utf-8"
        ).splitlines()

        logger.warning(
            "[RAM DEBUG] mountinfo total entries: %d",
            len(lines)
        )

        # Look specifically for cgroup mounts
        cgroup_lines = [
            line for line in lines
            if "cgroup" in line.lower()
        ]

        logger.warning(
            "[RAM DEBUG] cgroup mount entries: %d",
            len(cgroup_lines)
        )

        for line in cgroup_lines[:10]:
            logger.warning(
                "[RAM DEBUG] CGROUP MOUNT: %s",
                line[:1000]
            )

        # Show first few entries if no cgroup mounts found
        if not cgroup_lines:
            logger.warning(
                "[RAM DEBUG] No cgroup mounts detected"
            )

            for line in lines[:5]:
                logger.warning(
                    "[RAM DEBUG] MOUNT ENTRY: %s",
                    line[:1000]
                )

    except Exception as exc:
        logger.warning(
            "[RAM DEBUG] Cannot inspect mountinfo: %s",
            exc
        )

    # 5. Check standard Linux cgroup paths
    standard_paths = [
        "/sys/fs/cgroup",
        "/sys/fs/cgroup/memory.current",
        "/sys/fs/cgroup/memory.stat",
        "/sys/fs/cgroup/memory",
        "/sys/fs/cgroup/memory/memory.usage_in_bytes",
    ]

    for path in standard_paths:
        try:
            p = Path(path)

            logger.warning(
                "[RAM DEBUG] Standard path: %s | "
                "exists=%s | readable=%s",
                path,
                p.exists(),
                os.access(path, os.R_OK),
            )

        except Exception as exc:
            logger.warning(
                "[RAM DEBUG] Standard path error: %s",
                exc
            )

    logger.warning(
        "[RAM DEBUG] Diagnostics completed"
    )



def memory_mb():
    paths = _cgroup_paths()
    for path in paths:
        value = _read_int(path)
        if value is not None:
            return value / (1024 * 1024)
    _diagnose(paths)
    return None


def _worker():
    try:
        warn_mb = float(os.getenv("RAM_WARN_MB", "750"))
        restart_mb = float(os.getenv("RAM_RESTART_MB", "850"))
        interval = max(1.0, float(os.getenv("RAM_CHECK_SECONDS", "2")))
        confirm = max(1, int(os.getenv("RAM_CONFIRM_SAMPLES", "2")))
        grace = max(0.0, float(os.getenv("RAM_STARTUP_GRACE_SECONDS", "120")))
        dry_run = _env_bool("RAM_WATCHDOG_DRY_RUN", True)
    except ValueError:
        logger.exception("[RAM WATCHDOG] Invalid RAM_* setting; watchdog stopped")
        return

    logger.info(
        "[RAM WATCHDOG] settings: warn=%.0f MB restart=%.0f MB interval=%.1fs "
        "confirm=%d grace=%.0fs dry_run=%s",
        warn_mb, restart_mb, interval, confirm, grace, dry_run,
    )
    if restart_mb <= warn_mb:
        logger.warning("[RAM WATCHDOG] restart threshold is not above warning threshold")
    started_at = time.monotonic()
    consecutive = 0
    warned = False
    last_report = 0.0
    last_dry_run = 0.0

    while True:
        try:
            used = memory_mb()
            now = time.monotonic()
            if used is None:
                consecutive = 0
                if now - last_report >= 60:
                    logger.warning("[RAM WATCHDOG] cgroup memory metric unavailable; no restart action")
                    last_report = now
            else:
                if now - last_report >= 60:
                    logger.info("[RAM WATCHDOG] dyno cgroup memory %.1f MB", used)
                    last_report = now
                if used >= warn_mb and not warned:
                    logger.warning("[RAM WATCHDOG] high memory %.1f MB (warning %.0f MB)", used, warn_mb)
                    warned = True
                elif used < warn_mb:
                    warned = False

                if now - started_at < grace:
                    consecutive = 0
                elif used >= restart_mb:
                    consecutive += 1
                    if consecutive >= confirm:
                        if dry_run:
                            if now - last_dry_run >= 60:
                                logger.error(
                                    "[RAM WATCHDOG] %.1f MB >= %.0f MB for %d checks; "
                                    "DRY-RUN: would exit", used, restart_mb, consecutive,
                                )
                                last_dry_run = now
                        else:
                            logger.critical(
                                "[RAM WATCHDOG] %.1f MB >= %.0f MB for %d checks; "
                                "exiting main process", used, restart_mb, consecutive,
                            )
                            logging.shutdown()
                            os._exit(1)
                else:
                    consecutive = 0
        except Exception:
            consecutive = 0
            logger.exception("[RAM WATCHDOG] memory check failed; continuing")
        time.sleep(interval)


def start_ram_watchdog():
    """Start one daemon monitor thread. Call once, from the main bot process."""
    global _started
    if not _env_bool("RAM_WATCHDOG_ENABLED", True):
        logger.info("[RAM WATCHDOG] disabled")
        return
    with _lock:
        if _started:
            return
        _started = True
        thread = threading.Thread(target=_worker, name="ram-watchdog", daemon=True)
        thread.start()
        logger.info("[RAM WATCHDOG] started")
