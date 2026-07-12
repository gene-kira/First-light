import subprocess
import time
import ctypes
import sys
import os

# --- CONFIG ---
CHECK_INTERVAL = 3        # seconds between checks
LOGFILE = "mouse_watchdog.log"

# --- WINDOWS API ---
# Prevent system sleep on HID devices
ES_CONTINUOUS = 0x80000000
ES_SYSTEM_REQUIRED = 0x00000001

ctypes.windll.kernel32.SetThreadExecutionState(
    ES_CONTINUOUS | ES_SYSTEM_REQUIRED
)

def log(msg):
    with open(LOGFILE, "a") as f:
        f.write(msg + "\n")
    print(msg)

def restart_hid_driver():
    """
    Restart HID-compliant mouse driver using DevCon.
    DevCon is included in Windows Driver Kit, but Windows 11
    usually has the HID class available for restart.
    """
    log("[!] Mouse freeze detected — restarting HID driver")

    try:
        # Restart HID mouse class
        subprocess.run(
            ["devcon", "restart", "hidclass"],
            capture_output=True,
            text=True
        )
        log("[+] HID driver restarted")
    except Exception as e:
        log(f"[ERROR] Could not restart HID driver: {e}")

def check_mouse():
    """
    Check if mouse is responding by querying raw input devices.
    If the mouse disappears from the list, trigger a restart.
    """
    try:
        result = subprocess.run(
            ["powershell", "-command",
             "Get-PnpDevice -Class Mouse | Select-Object Status"],
            capture_output=True,
            text=True
        )

        output = result.stdout.lower()

        if "ok" not in output:
            log("[!] Mouse status not OK — possible disconnect")
            restart_hid_driver()
        else:
            log("[OK] Mouse stable")

    except Exception as e:
        log(f"[ERROR] Mouse check failed: {e}")

def main():
    log("=== Mouse Watchdog Started ===")
    while True:
        check_mouse()
        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    main()
