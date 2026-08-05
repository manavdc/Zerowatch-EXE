import sys
if sys.platform == "win32":
    import winreg
else:
    winreg = None

import uuid
import subprocess
import json
import datetime
import os
import csv
import time
import threading
from multiprocessing import Process, freeze_support

# --- Module: Fingerprint & Identity ---

def get_mac_address():
    """Generates a formatted MAC address string."""
    mac_num = hex(uuid.getnode()).replace('0x', '').upper()
    mac = '-'.join(mac_num[i: i + 2] for i in range(0, 11, 2))
    return mac

def get_bios_uuid():
    """Fetches the BIOS UUID via WMIC."""
    try:
        # Using wmic avoids needing heavy third-party wmi packages
        output = subprocess.check_output(['wmic', 'csproduct', 'get', 'uuid'], creationflags=subprocess.CREATE_NO_WINDOW, stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL).decode('utf-8')
        # Output is usually: \nUUID\n<actual-uuid>\n
        lines = [line.strip() for line in output.split('\n') if line.strip()]
        if len(lines) >= 2:
            return lines[1]
    except Exception as e:
        print(f"Warning: Could not get BIOS UUID - {e}")
    return "UNKNOWN_BIOS_UUID"

def get_motherboard_serial():
    """Fetches the Motherboard Serial Number via WMIC."""
    try:
        output = subprocess.check_output(['wmic', 'baseboard', 'get', 'serialnumber'], creationflags=subprocess.CREATE_NO_WINDOW, stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL).decode('utf-8')
        lines = [line.strip() for line in output.split('\n') if line.strip()]
        if len(lines) >= 2:
            return lines[1]
    except Exception as e:
        print(f"Warning: Could not get Motherboard Serial - {e}")
    return "UNKNOWN_MB_SERIAL"

def get_machine_guid():
    """Fetches the Windows Machine GUID from the registry."""
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography")
        guid = winreg.QueryValueEx(key, "MachineGuid")[0]
        winreg.CloseKey(key)
        return str(guid).strip()
    except Exception as e:
        print(f"Warning: Could not get Machine GUID - {e}")
    return "UNKNOWN_MACHINE_GUID"

def get_cpu_id():
    """Fetches the Processor ID via WMIC."""
    try:
        output = subprocess.check_output(['wmic', 'cpu', 'get', 'processorid'], creationflags=subprocess.CREATE_NO_WINDOW, stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL).decode('utf-8')
        lines = [line.strip() for line in output.split('\n') if line.strip()]
        if len(lines) >= 2:
            return lines[1]
    except Exception as e:
        print(f"Warning: Could not get CPU ID - {e}")
    return "UNKNOWN_CPU_ID"

def get_disk_serial():
    """Fetches the primary Disk Drive Serial Number via WMIC."""
    try:
        output = subprocess.check_output(['wmic', 'diskdrive', 'get', 'serialnumber'], creationflags=subprocess.CREATE_NO_WINDOW, stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL).decode('utf-8')
        lines = [line.strip() for line in output.split('\n') if line.strip()]
        if len(lines) >= 2:
            # First drive is usually the primary
            return lines[1].strip()
    except Exception as e:
        print(f"Warning: Could not get Disk Serial - {e}")
    return "UNKNOWN_DISK_SERIAL"

def get_fingerprint():
    """Returns the composite device identity fingerprint."""
    return {
        "mac_address": get_mac_address(),
        "bios_uuid": get_bios_uuid(),
        "motherboard_serial": get_motherboard_serial(),
        "machine_guid": get_machine_guid(),
        "cpu_id": get_cpu_id(),
        "disk_serial": get_disk_serial()
    }

# --- Module: Scraper (Windows Registry) ---

def get_installed_software():
    """Scrapes the Windows Registry for installed applications."""
    software_list = []
    
    # We check standard x64 keys, WOW6432Node (x86 apps on x64), and CurrentUser keys.
    registry_paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
    ]
    
    for hkey, target_path in registry_paths:
        try:
            key = winreg.OpenKey(hkey, target_path)
            # Iterate over all subkeys
            for i in range(0, winreg.QueryInfoKey(key)[0]):
                try:
                    skey_name = winreg.EnumKey(key, i)
                    skey = winreg.OpenKey(key, skey_name)
                    
                    try:
                        # DisplayName is the only truly required field for us to care about it
                        name = winreg.QueryValueEx(skey, "DisplayName")[0]
                        
                        # Try to grab secondary metadata safely
                        version, publisher, install_date = "", "", ""
                        try: version = winreg.QueryValueEx(skey, "DisplayVersion")[0]
                        except: pass
                        try: publisher = winreg.QueryValueEx(skey, "Publisher")[0]
                        except: pass
                        try: install_date = winreg.QueryValueEx(skey, "InstallDate")[0]
                        except: pass
                        
                        if str(name).strip():
                            software_list.append({
                                "name": str(name).strip(),
                                "version": str(version).strip(),
                                "publisher": str(publisher).strip(),
                                "registry_path": f"{target_path}\\{skey_name}"
                            })
                    except Exception:
                        pass # Ignore unnamed keys
                    finally:
                        skey.Close()
                except Exception:
                    continue
            key.Close()
        except Exception:
            pass # Ignore paths that don't exist

    # Deduplicate by name and version
    unique_software = []
    seen = set()
    for app in software_list:
        identifier = f"{app['name']}::{app['version']}"
        if identifier not in seen:
            seen.add(identifier)
            unique_software.append(app)

    return unique_software

# --- Local File Exports ---

def export_to_readable_files(fingerprint, software_list):
    """Exports the fingerprint and software inventory to readable files (CSV & JSON)."""
    mac = fingerprint.get("mac_address", "UNKNOWN").replace("-", "")
    
    fp_filename = f"fingerprint_{mac}.json"
    with open(fp_filename, 'w') as f:
        json.dump(fingerprint, f, indent=4)
    print(f"-> Saved fingerprint to {fp_filename}")
        
    csv_filename = f"software_{mac}.csv"
    if software_list:
        keys = software_list[0].keys()
        with open(csv_filename, 'w', newline='', encoding='utf-8') as output_file:
            dict_writer = csv.DictWriter(output_file, keys)
            dict_writer.writeheader()
            dict_writer.writerows(software_list)
        print(f"-> Saved software inventory to {csv_filename}")

# --- Module: Safe Real-Time Monitoring (Registry Polling) ---

def monitor_software_changes(fingerprint):
    """
    Safely polls the registry for changes every 20 seconds.
    WMI Win32_Product is notoriously unstable and causes RPC COM errors on Windows 10/11.
    """
    # Keep track of the last known software count
    last_known_count = len(get_installed_software())
    
    while True:
        try:
            time.sleep(20) # Check every 20 seconds
            
            # Grabbing just the count is very fast and uses no CPU
            current_software = get_installed_software()
            current_count = len(current_software)
            
            if current_count != last_known_count:
                export_to_readable_files(fingerprint, current_software)
                last_known_count = current_count
                
        except Exception:
            time.sleep(20)

# --- Module: Infallible Watchdog & Password Prompt ---

def prompt_password_to_quit():
    """
    This runs ALONE in a completely fresh visible console.
    """
    print("="*60)
    print(" SECURITY ALERT: UNAUTHORIZED TERMINATION ATTEMPT DETECTED")
    print(" Endpoint Agent is locked and requires an administrative override.")
    print("="*60 + "\n")
    
    pwd = None
    try:
        # Ask for password
        pwd = input("Enter termination password (Pass@123) to exit securely: ")
    except Exception:
         pass
         
    if pwd == "Pass@123":
        print("\n[✓] Password accepted. Terminating watchdog and agent permanently...")
        time.sleep(2)
        sys.exit(0)
    else:
        print("\n[X] Incorrect password! Termination denied.")
        print("This window will self-destruct in 5 seconds...")
        time.sleep(5)
        sys.exit(1)

def watchdog_process(target_exe_path):
    """
    This detached background process stays completely invisible.
    It watches the main sensor (agent). If the user kills the sensor via Task Manager,
    the watchdog instantly detects it, pops open a visible CLI asking for the password.
    If the password fails, it silently revives the sensor.
    """
    time.sleep(2) 
    executable_name = os.path.basename(target_exe_path)
    
    while True:
        try:
            # We check how many instances of our executable are running.
            # Normal state: 2 instances (1 Watchdog, 1 Main Sensor)
            output = subprocess.check_output(['tasklist', '/FI', f'IMAGENAME eq {executable_name}'], creationflags=subprocess.CREATE_NO_WINDOW, stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL).decode('utf-8')
            count = output.lower().count(executable_name.lower())
            
            # If count is less than 2, the user killed the Main Sensor!
            if count < 2:
                prompt_exe = sys.executable
                if "python" in prompt_exe.lower():
                     prompt_args = [prompt_exe, os.path.abspath(__file__), "--password-prompt"]
                else:
                     prompt_args = [prompt_exe, "--password-prompt"]
                
                # 1. Spawn the password prompt VISIBLY and block until it finishes
                # CREATE_NEW_CONSOLE ensures it pops up visibly right in front of the user
                exit_code = subprocess.call(prompt_args, creationflags=subprocess.CREATE_NEW_CONSOLE)
                
                if exit_code == 0:
                     # Authorised kill. Shut down the watchdog.
                     sys.exit(0)
                else:
                     # Password failed or window closed. Revive the main sensor silently.
                     # 0x00000008 = DETACHED_PROCESS, 0x00000200 = CREATE_NEW_PROCESS_GROUP
                     revive_flags = subprocess.CREATE_NO_WINDOW | 0x00000008 | 0x00000200
                     subprocess.Popen([target_exe_path], creationflags=revive_flags)
                     time.sleep(3)
            
            time.sleep(3)
        except Exception:
            time.sleep(3)

# --- Main Entry Point ---

def main_agent():
    """
    This is the core sensor. It runs completely silently in the background.
    """
    # Hide the main agent's console window entirely so the user never sees it
    import ctypes
    whnd = ctypes.windll.kernel32.GetConsoleWindow()
    if whnd != 0:
        ctypes.windll.user32.ShowWindow(whnd, 0) # 0 = SW_HIDE
        
    fingerprint = get_fingerprint()
    software = get_installed_software()
    export_to_readable_files(fingerprint, software)
    
    # Run the safe registry monitor in a daemon thread
    monitor_thread = threading.Thread(target=monitor_software_changes, args=(fingerprint,), daemon=True)
    monitor_thread.start()
    
    # Infinite loop to keep the process alive invisibly
    try:
        while True:
            time.sleep(60)
            # Future: API Sync calls go here
    except Exception:
        sys.exit(0)

def main():
    """
    Entry point resolver.
    """
    if sys.platform != "win32":
        import sentinel_agent
        sentinel_agent.main()
        return

    freeze_support() # Required for multiprocessing in compiled Windows EXEs
    
    # 1. Did we get invoked to show the password prompt?
    if len(sys.argv) > 1 and sys.argv[1] == "--password-prompt":
         prompt_password_to_quit()
         return
         
    # 2. Did we get invoked as the Watchdog?
    is_watchdog = len(sys.argv) > 1 and sys.argv[1] == "--watchdog"
    
    if is_watchdog:
         # I am the silent watchdog process. 
         target_exe = sys.argv[2] if len(sys.argv) > 2 else sys.executable
         watchdog_process(target_exe)
    else:
         # 3. I am the initial Main Agent.
         current_exe = sys.executable
         
         if "python" in current_exe.lower():
              watchdog_args = [current_exe, os.path.abspath(__file__), "--watchdog", "python.exe"]
         else:
              watchdog_args = [current_exe, "--watchdog", current_exe]
              
         # Spawn the watcher completely detached and invisible
         # We use DETACHED_PROCESS and CREATE_NEW_PROCESS_GROUP so Task Manager doesn't kill both together
         spawn_flags = subprocess.CREATE_NO_WINDOW | 0x00000008 | 0x00000200
         subprocess.Popen(watchdog_args, creationflags=spawn_flags)
         
         # Start actual silent agent payload
         main_agent()

if __name__ == "__main__":
    main()
