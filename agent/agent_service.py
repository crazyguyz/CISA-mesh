"""
Windows Service Wrapper for GIAM-SAT Agent
Allows the agent to run as a Windows service (autostart with Windows)
"""

import sys
import os
import time
import threading

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Try to import servicemanager for Windows service support
try:
    import servicemanager
    import win32serviceutil
    import win32service
    import win32event
    HAS_SERVICE = True
except ImportError:
    HAS_SERVICE = False
    print("[!] pywin32 service modules not available. Running in console mode.")


class GiamSatAgentService(win32serviceutil.ServiceFramework):
    """Windows Service for GIAM-SAT Agent."""
    _svc_name_ = "GiamSatAgent"
    _svc_display_name_ = "GIAM-SAT Agent - Giám sát bảo mật"
    _svc_description_ = "Thu thập log Windows, giám sát file và thực thi phản hồi tự động từ Server trung tâm."

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.agent = None

    def SvcStop(self):
        """Stop the service."""
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)
        if self.agent:
            self.agent.running = False
            if self.agent.event_collector:
                self.agent.event_collector.stop()
            if self.agent.fim_collector:
                self.agent.fim_collector.stop()
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STOPPED,
            (self._svc_name_, "Service stopped.")
        )

    def SvcDoRun(self):
        """Run the service."""
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, "Service started.")
        )
        self.main()

    def main(self):
        """Agent main loop inside service."""
        try:
            # Ensure Task Scheduler entry for logon auto-start (AC & battery)
            try:
                from task_scheduler import ensure_task
                ensure_task()
            except Exception as e:
                servicemanager.LogMsg(
                    servicemanager.EVENTLOG_WARNING_TYPE,
                    servicemanager.PYS_SERVICE_STARTED,
                    (self._svc_name_, f"Task Scheduler skipped: {e}")
                )

            from agent_core import AgentCore
            self.agent = AgentCore()
            self.agent.start()
        except Exception as e:
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_ERROR_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, f"Error: {str(e)}")
            )


def run_as_service():
    """Run the agent as a Windows service."""
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(GiamSatAgentService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(GiamSatAgentService)


def run_as_console():
    """Run the agent in console mode."""
    from agent_core import AgentCore
    agent = AgentCore()
    agent.start()


if __name__ == "__main__":
    if HAS_SERVICE and "install" in sys.argv or "start" in sys.argv or "stop" in sys.argv or "remove" in sys.argv:
        run_as_service()
    else:
        run_as_console()
