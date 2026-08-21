"""
Run Script for GIAM-SAT Server
"""

import sys
import os


def _load_env_file():
    """Load server/.env so the server always has GIAMSAT_*/TELEGRAM_*/DEEPSEEK_*
    regardless of how it was started (python-dotenv preferred, manual fallback).
    v4.14: previously the .env was never loaded by the server itself - env vars only
    existed if the launching shell had them, so a plain restart could silently lose
    GIAMSAT_AGENT_PSK / GIAMSAT_COMMAND_KEY and break agent auth (401) + update
    signing (503)."""
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if not os.path.exists(env_path):
        return
    try:
        from dotenv import load_dotenv
        # utf-8-sig strips a UTF-8 BOM so the first key is not mangled
        with open(env_path, "r", encoding="utf-8-sig") as _f:
            load_dotenv(stream=_f, override=False)
        return
    except ImportError:
        pass
    # Manual fallback (no python-dotenv installed)
    try:
        with open(env_path, "r", encoding="utf-8-sig") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                k = k.strip().strip("﻿")
                v = v.strip().strip(chr(34)).strip(chr(39))
                if k and k not in os.environ:
                    os.environ[k] = v
    except Exception:
        pass

if __name__ == "__main__":
    _load_env_file()
    from server_core import ServerCore

    web_port = 5000
    if len(sys.argv) > 1:
        try:
            web_port = int(sys.argv[1])
        except ValueError:
            pass

    import webbrowser
    import threading

    def open_browser():
        import time
        time.sleep(2)
        webbrowser.open(f"http://127.0.0.1:{web_port}")

    threading.Thread(target=open_browser, daemon=True).start()

    server = ServerCore(web_host="0.0.0.0", web_port=web_port)
    server.start()
