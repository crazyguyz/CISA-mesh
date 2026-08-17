"""
Run Script for GIAM-SAT Server
"""

import sys
import os

if __name__ == "__main__":
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
