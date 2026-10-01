"""Pytest collection guards - v5.0.8 (Phase D).

The suites in tests/ were written to be run directly and two of them cannot run
outside Windows:

  * alert_quality_tests.py  - imports the agent modules (pywin32) and calls
    sys.exit(0) at import time on other platforms, which would abort the whole
    pytest session (SystemExit is not a test failure).
  * agent_memory_tests.py   - same agent-side imports.

Instead of letting one suite kill collection, ignore them here when the platform
cannot support them, so `pytest tests` still runs everything else.
"""

import os

collect_ignore = []
if os.name != "nt":
    collect_ignore += ["alert_quality_tests.py", "agent_memory_tests.py"]
