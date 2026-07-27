import time
import psutil
import datetime

TARGETS = [
    "chrome.exe",
    "google chrome for testing.exe",
    "pdpro7 hook.exe",
]

LOG_FILE = "chrome_pdpro_killer_log.txt"

def log(msg):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass

def is_target(name: str) -> bool:
    if not name:
        return False
    lname = name.lower()
    for t in TARGETS:
        if t.lower() in lname:
            return True
    return False

def kill_targets_once():
    killed = 0
    for proc in psutil.process_iter(["name", "pid"]):
        try:
            name = proc.info["name"]
            pid = proc.info["pid"]
            if not name:
                continue

            if is_target(name):
                try:
                    psutil.Process(pid).terminate()
                    log(f"KILLED target process: {name} (PID={pid})")
                    killed += 1
                except Exception as e:
                    log(f"Failed to kill {name} (PID={pid}): {e}")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return killed

def main():
    log("Chrome / pdpro7 killer starting (auto-kill instantly)")
    while True:
        killed = kill_targets_once()
        if killed == 0:
            # nothing found this cycle
            time.sleep(1.0)
        else:
            # if we killed something, wait a bit then re-scan
            time.sleep(0.5)

if __name__ == "__main__":
    main()
