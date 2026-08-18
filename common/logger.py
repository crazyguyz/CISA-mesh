"""
GIAM-SAT Unified Logging Utility.
Replaces all print() and except Exception: pass with structured logging.
"""
import logging
import os
import sys
import traceback

_initialized = False
_logger = None


def _init_logging():
    """Initialize logging once."""
    global _initialized, _logger

    if _initialized:
        return

    # Determine log directory
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    log_dir = os.path.join(base_dir, "logs")
    try:
        os.makedirs(log_dir, exist_ok=True)
    except Exception:
        log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
        os.makedirs(log_dir, exist_ok=True)

    _logger = logging.getLogger("giamsat")
    _logger.setLevel(logging.DEBUG)

    # File handler - all logs
    fh = logging.FileHandler(os.path.join(log_dir, "giamsat.log"), encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s.%(funcName)s:%(lineno)d - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))

    # Console handler - INFO and above
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter(
        "[%(levelname)s] %(message)s"
    ))

    _logger.addHandler(fh)
    _logger.addHandler(ch)

    _initialized = True


def get_logger(name=None):
    """Get a logger instance."""
    _init_logging()
    if name:
        return logging.getLogger(f"giamsat.{name}")
    return _logger


def log_error(message, exc=None, context=None):
    """
    Log an error with optional exception details and context dict.
    This replaces 'except Exception: pass' patterns.

    Usage:
        try:
            ...
        except Exception as e:
            log_error("Failed to connect", exc=e, context={"host": host, "port": port})
    """
    _init_logging()
    logger = _logger

    parts = [f"ERROR: {message}"]
    if context:
        parts.append(f"  Context: {context}")
    if exc:
        parts.append(f"  Exception: {type(exc).__name__}: {exc}")
        # Get the last frame of the traceback for location info
        tb = traceback.extract_tb(exc.__traceback__)
        if tb:
            last = tb[-1]
            parts.append(f"  Location: {last.filename}:{last.lineno} in {last.name}")
        parts.append(f"  Traceback:\n{traceback.format_exc()}")

    logger.error("\n".join(parts))


def log_warning(message, context=None):
    """Log a warning message."""
    _init_logging()
    parts = [f"WARNING: {message}"]
    if context:
        parts.append(f"  Context: {context}")
    _logger.warning("\n".join(parts))


def log_info(message):
    """Log an info message (replaces print())."""
    _init_logging()
    _logger.info(message)


def log_debug(message, context=None):
    """Log a debug message."""
    _init_logging()
    parts = [f"DEBUG: {message}"]
    if context:
        parts.append(f"  Context: {context}")
    _logger.debug("\n".join(parts))


_print_tee_installed = False


def setup_file_logging():
    """Tee print() to logs/giamsat.log so ALL server console output is persisted.

    The server uses print() extensively (not the logging module), so this
    redirects print to also append to the log file while keeping the original
    console output. Idempotent (safe to call multiple times)."""
    global _print_tee_installed
    if _print_tee_installed:
        return
    _print_tee_installed = True
    try:
        import builtins as _bi
        import threading as _threading
        from datetime import datetime as _dt

        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        log_file = os.path.join(base_dir, "logs", "giamsat.log")
        os.makedirs(os.path.dirname(log_file), exist_ok=True)

        _orig_print = _bi.print
        _lock = _threading.Lock()
        # v4.10 (LOW-12): keep the file open instead of open/close on every print,
        # and rotate when it grows past 20MB (the old tee never rotated and could
        # fill the disk).
        _MAX_LOG_BYTES = 20 * 1024 * 1024

        def _rotate():
            nonlocal log_file
            try:
                _fh.close()
                backup = log_file + ".1"
                if os.path.exists(backup):
                    os.remove(backup)
                os.rename(log_file, backup)
            except Exception:
                pass
            return open(log_file, "a", encoding="utf-8")

        _fh = open(log_file, "a", encoding="utf-8")

        def _tee(*args, **kwargs):
            nonlocal _fh
            try:
                msg = " ".join(str(a) for a in args)
                line = f"[{_dt.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
                with _lock:
                    try:
                        if _fh.tell() > _MAX_LOG_BYTES:
                            _fh = _rotate()
                        _fh.write(line + "\n")
                        _fh.flush()
                    except Exception:
                        pass
            except Exception:
                pass
            try:
                _orig_print(*args, **kwargs)
            except Exception:
                pass

        _bi.print = _tee
    except Exception:
        pass


# v2.5.1 SECURITY FIX: Replaces 100+ bare except: pass blocks
# Usage in existing code:
#
#   OLD (BAD):                          NEW (GOOD):
#   try:                                try:
#       do_something()                       do_something()
#   except Exception:                    except Exception as e:
#       pass                                 log_error("do_something failed", exc=e)