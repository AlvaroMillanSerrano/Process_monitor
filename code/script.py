import os
import sys
import psutil
import time

def detect_os() -> str:
    system = sys.platform
    print(f"[+] Detected OS: {system}")
    print(f"[+] Script's process ID: {os.getpid()}\n")
    return system

def list_process():
    print(f"{'PID':<10} {'Name':<35} {'User':<20} {'CPU (%)':<10} {'Memory (%)':<10}")
    print("-" * 85)

    for proc in psutil.process_iter(['cpu_percent']):
        try: proc.info['cpu_percent']
        except: pass
    time.sleep(0.1)
    
    for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
        try:
            info = proc.info
            user = info['username'] if info['username'] else "N/A"
            cpu = info['cpu_percent'] if info['cpu_percent'] else 0.0
            mem = info['memory_percent'] if info['memory_percent'] else 0.0
            
            print(f"{info['pid']:<10} {info['name']:<35} {user:<20} {cpu:<10.1f} {mem:<10.1f}")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

def search_process(p_name):
    print(f"\n[?] Searching process containing '{p_name}' in its name:")
    found = False
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            if p_name.lower() in proc.info['name'].lower():
                print(f" -> PID: {proc.info['pid']} | Name: {proc.info['name']} | Route: {proc.info['exe']}")
                found = True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    if not found:
        print("Process not found.")

def analyze_sus(so):
    p_anomalies = False
    print("\n[?] Analyzing possible anomalies...")

    for proc in psutil.process_iter(['cpu_percent']):
        try: proc.info['cpu_percent']
        except: pass
    time.sleep(0.1)
    
    sus_names = ["miner", "crypto", "exploit", "hack", "keylogger"]
    sus_routes_win = ["\\appdata\\local\\temp", "\\users\\public"]
    sus_routes_lin = ["/tmp", "/dev/shm", "/var/tmp"]
    critical_win_procs = ["svchost.exe", "lsass.exe", "services.exe", "lsm.exe", "csrss.exe"]

    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cpu_percent']):
        try:
            pid = proc.info['pid']
            name = proc.info['name']
            route = proc.info['exe'] if proc.info['exe'] else ""
            cpu = proc.info['cpu_percent'] if proc.info['cpu_percent'] else 0.0

            if cpu > 80.0:
                print(f"[!]-> ALERT: PID {pid} ({name}) consumes {cpu}% CPU.")
                p_anomalies = True

            if any(sus in name.lower() for sus in sus_names):
                print(f"[!]-> ALERT: Suspicious names detected -> PID {pid}: {name}")
                p_anomalies = True

            if so.startswith("win"):
                if any(sus_route in route.lower() for sus_route in sus_routes_win):
                    print(f"[!]-> ALERT: Process executing from windows temp folder -> PID {pid}: {name} ({route})")
                    p_anomalies = True
                if name_lower in critical_win_procs and "system32" not in route_lower:
                    if pid != 4 and route != "":
                        print(f"[!!!]-> CRITICAL ALERT: Fake System Process! -> PID {pid}: {name} running from {route}")
                        p_anomalies = True
    
            elif so.startswith("linux"):
                if any(sus_route in route.lower() for sus_route in sus_routes_lin):
                    print(f"[!]-> ALERT: Process executing from linux temp folder -> PID {pid}: {name} ({route})")
                    p_anomalies = True

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    if not p_anomalies:
        print("No anomaly detected, all clean")

if __name__ == "__main__":
    current_os = detect_os()
    opt = 0
    while opt != 4:
        try:
            print("--- PROCESS MONITOR ---")
            print("1. List active processes")
            print("2. Analyze process by name")
            print("3. Search for suspicious processes")
            print("4. Quit")
            opt = int(input("Choice? (1-4):"))
            if opt == 1:
                process_list = list_process()
                input("\npress enter to return")
            elif opt == 2:
                name = input("Introduce process name: ")
                search_process(name)
                input("\npress enter to return")
            elif opt == 3:
                analyze_sus(current_os)
                input("\npress enter to return")
            if opt > 4 or opt < 1:
                raise ValueError
            if (opt != 4):
                os.system('cls' if os.name == 'nt' else 'clear')
        except Exception:
            os.system('cls' if os.name == 'nt' else 'clear')
            print("invalid option")
            opt = 0
    print("bye")