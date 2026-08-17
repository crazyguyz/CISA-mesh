"""
Task Scheduler for GIAM-SAT Agent
v2.5.26: Use schtasks /Create command-line (not XML) for reliable logon trigger.
XML tasks require saved password for UserId-specific triggers - command-line handles this automatically.
"""
import subprocess
import os
import sys
import json

TASK_NAME = "GiamSatAgentStartup"
TASK_DESC = "GIAM-SAT Agent - Tự khởi động khi người dùng đăng nhập"


def get_agent_script_path():
    """Get the path to the agent's main.py or executable."""
    if getattr(sys, 'frozen', False):
        return sys.executable
    else:
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), "main.py")


def _run_schtasks(args):
    """Run schtasks.exe with given arguments."""
    try:
        cmd = ["schtasks.exe"] + args
        proc = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=30,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        return proc.returncode == 0, proc.stdout.strip(), proc.stderr.strip()
    except Exception as e:
        return False, "", str(e)


def check_task_exists():
    """Check if the scheduled task already exists."""
    success, stdout, _ = _run_schtasks(["/Query", "/TN", TASK_NAME, "/FO", "LIST", "/V"])
    return success


def create_task():
    """
    v2.5.26: Use schtasks /Create command-line (not XML).
    XML tasks require saved passwords for UserId triggers - command-line handles this.
    Runs at any user logon with user's own privileges.
    """
    script_path = get_agent_script_path()

    # Direct EXE path - no cmd /c, no start /MIN
    if getattr(sys, 'frozen', False):
        task_cmd = f'"{script_path}"'
    else:
        task_cmd = f'"{sys.executable}" "{script_path}"'

    # Try ONLOGON trigger (runs at any user logon)
    success, stdout, stderr = _run_schtasks([
        "/Create", "/TN", TASK_NAME,
        "/TR", task_cmd,
        "/SC", "ONLOGON",
        "/RL", "HIGHEST",
        "/F"
    ])

    if success:
        print(f"[+] Task Scheduler created: '{TASK_NAME}' (ONLOGON)")
        print(f"[+] Command: {task_cmd}")
        return True
    else:
        print(f"[-] ONLOGON failed: {stderr}")

        # Fallback: AT LOGON trigger
        success2, stdout2, stderr2 = _run_schtasks([
            "/Create", "/TN", TASK_NAME,
            "/TR", task_cmd,
            "/SC", "ONLOGON",
            "/F"
        ])
        if success2:
            print(f"[+] Task Scheduler created: '{TASK_NAME}' (ONLOGON, no RL)")
            return True
        print(f"[-] ONLOGON (no RL) failed: {stderr2}")
        return False


def remove_task():
    """Remove the scheduled task."""
    success, stdout, stderr = _run_schtasks(["/Delete", "/TN", TASK_NAME, "/F"])
    if success:
        print(f"[+] Task Scheduler removed: '{TASK_NAME}'")
    else:
        print(f"[-] Failed to remove task: {stderr}")
    return success


def ensure_task():
    """v2.5.26: Remove old task (XML-based) and recreate with command-line."""
    if check_task_exists():
        remove_task()
        print(f"[*] Removed old task, recreating with schtasks command-line...")
    return create_task()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "create":
            create_task()
        elif sys.argv[1] == "remove":
            remove_task()
        elif sys.argv[1] == "check":
            exists = check_task_exists()
            print(f"Task exists: {exists}")
        else:
            print("Usage: python task_scheduler.py [create|remove|check]")
    else:
        ensure_task()