"""
remediation.py
--------------
Pushes configuration fixes to real Cisco devices via SSH.
Called by ai_agent.py when gemini decides to AUTO-FIX.
"""

from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
from config import DEVICES
from datetime import datetime


def get_device_config(host: str) -> dict | None:
    """Look up device credentials by IP from config.py"""
    for d in DEVICES:
        if d["host"] == host:
            return d
    return None


def fix_interface(host: str, interface: str) -> bool:
    """
    SSH into device and run 'no shutdown' on the specified interface.
    Returns True on success, False on failure.
    """
    device_config = get_device_config(host)
    if not device_config:
        print(f"  ❌ No config found for host {host}")
        return False

    print(f"  Connecting to {host} to fix {interface}...")
    try:
        conn = ConnectHandler(**{k: v for k, v in device_config.items() if k != "name"})
        conn.enable()

        # Push the fix
        commands = [
            f"interface {interface}",
            "no shutdown"
        ]
        output = conn.send_config_set(commands)
        conn.save_config()  # write memory
        conn.disconnect()

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"  [{timestamp}] Applied: no shutdown on {interface} @ {host}")
        print(f"  Device output: {output.strip()}")
        return True

    except NetmikoTimeoutException:
        print(f"  ❌ Timeout connecting to {host}")
        return False
    except NetmikoAuthenticationException:
        print(f"  ❌ Auth failed for {host} — check config.py")
        return False
    except Exception as e:
        print(f"  ❌ Remediation error: {e}")
        return False


def push_commands(host: str, commands: list) -> tuple[bool, str]:
    """
    Generic function to push any list of config commands to a device.
    Used by drift_detector.py for rollback.
    Returns (success, output).
    """
    device_config = get_device_config(host)
    if not device_config:
        return False, f"No config found for host {host}"

    try:
        conn = ConnectHandler(**{k: v for k, v in device_config.items() if k != "name"})
        conn.enable()
        output = conn.send_config_set(commands)
        conn.save_config()
        conn.disconnect()
        return True, output
    except Exception as e:
        return False, str(e)


# --- Test standalone ---
if __name__ == "__main__":
    print("=== Remediation Test ===")
    host = input("Enter device IP: ")
    interface = input("Enter interface (e.g. GigabitEthernet0/0): ")
    result = fix_interface(host, interface)
    print("Success" if result else "Failed")
