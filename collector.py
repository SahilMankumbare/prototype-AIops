"""
collector.py
------------
Polls real Cisco devices via SSH using Netmiko.
Returns structured interface status data for the AI agent and dashboard.
"""

import json
import re
import time
from datetime import datetime
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
from config import DEVICES, POLL_INTERVAL


def parse_interfaces(raw_output: str) -> dict:
    """
    Parse 'show interfaces' output into a clean dict.
    Returns: { "GigabitEthernet0/0": { "status": "up", "protocol": "up", "description": "..." } }
    """
    interfaces = {}
    # Match lines like: GigabitEthernet0/0 is up, line protocol is up
    # Using a simpler split-based or robust multi-line regex
    # This regex looks for the interface name and then the statuses, allowing for potential newlines/spaces
    pattern = r'^(\S+)\s+is\s+([\w\s]+),\s+line protocol is\s+(\w+)'
    
    for match in re.finditer(pattern, raw_output, re.MULTILINE):
        name = match.group(1)
        link_status = match.group(2)
        protocol_status = match.group(3)

        # Normalize link_status (handles "administratively down")
        link_up = "up" in link_status.lower() and "down" not in link_status.lower() or link_status.lower() == "up"
        proto_up = protocol_status.lower() == "up"

        status = "up" if link_up and proto_up else "down"
        interfaces[name] = {
            "status": status,
            "link": link_status.strip(),
            "protocol": protocol_status,
            "description": ""
        }

    # Second pass: get descriptions
    desc_pattern = re.compile(r'Description: (.+)', re.MULTILINE)
    # (simplified — in production, parse per-interface block)

    return interfaces


def parse_acls(raw_output: str) -> dict:
    """
    Parse 'show access-lists' output into a dict.
    Returns: { "1": {"type": "standard", "rules": [{"seq": "10", "action": "permit", "src": "192.168.1.0 0.0.0.255"}] } }
    """
    acls = {}
    lines = raw_output.split('\n')
    current_acl = None
    for line in lines:
        line = line.strip()
        if not line:
            continue
        # Match ACL header: Standard IP access list 1 or Extended IP access list 100
        match = re.match(r'(Standard|Extended) IP access list (\d+)', line)
        if match:
            acl_type = match.group(1).lower()
            acl_num = match.group(2)
            current_acl = acl_num
            acls[acl_num] = {"type": acl_type, "rules": []}
        elif current_acl and line[0].isdigit():  # Rule line starts with seq number
            # Parse rule: 10 permit 192.168.1.0, wildcard bits 0.0.0.255
            parts = line.split()
            if len(parts) >= 3:
                seq = parts[0]
                action = parts[1]
                if acl_type == "standard":
                    src = ' '.join(parts[2:])  # e.g., 192.168.1.0, wildcard bits 0.0.0.255
                    rule = {"seq": seq, "action": action, "src": src}
                else:  # extended
                    # Assume: 10 deny ip src wildcard dst wildcard
                    if len(parts) >= 6:
                        protocol = parts[2]
                        src = f"{parts[3]} {parts[4]}"
                        dst = f"{parts[5]} {parts[6]}"
                        rule = {"seq": seq, "action": action, "protocol": protocol, "src": src, "dst": dst}
                    else:
                        rule = {"seq": seq, "action": action, "raw": line}
                acls[current_acl]["rules"].append(rule)
    return acls


def poll_device(device_config: dict) -> dict:
    """
    SSH into a device, run show commands, return structured data.
    """
    result = {
        "name": device_config["name"],
        "host": device_config["host"],
        "timestamp": datetime.now().isoformat(),
        "reachable": False,
        "interfaces": {},
        "error": None
    }

    try:
        print(f"  Connecting to {device_config['name']} ({device_config['host']})...")
        # Added global_delay_factor to handle slow EVE-NG responses
        connection_params = {k: v for k, v in device_config.items() if k != "name"}
        conn = ConnectHandler(**connection_params, global_delay_factor=2)
        conn.enable()  # Enter enable mode

        # Get interface status
        raw = conn.send_command("show interfaces")
        result["interfaces"] = parse_interfaces(raw)

        # Get ACLs
        acl_raw = conn.send_command("show access-lists")
        result["acls"] = parse_acls(acl_raw)

        result["reachable"] = True

        # Get hostname from device
        hostname_raw = conn.send_command("show running-config | include hostname")
        result["hostname"] = hostname_raw.replace("hostname", "").strip() or device_config["name"]

        conn.disconnect()
        print(f"  ✅ {device_config['name']}: {len(result['interfaces'])} interfaces, {len(result['acls'])} ACLs polled")

    except NetmikoTimeoutException:
        result["error"] = f"Timeout — device {device_config['host']} unreachable"
        print(f"  ⚠️  {device_config['name']}: Timeout")
    except NetmikoAuthenticationException:
        result["error"] = "Authentication failed — check username/password in config.py"
        print(f"  ❌ {device_config['name']}: Auth error")
    except Exception as e:
        result["error"] = str(e)
        print(f"  ❌ {device_config['name']}: {e}")

    return result


def poll_all_devices() -> list:
    """Poll every device in config.py and return a list of results."""
    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Polling {len(DEVICES)} device(s)...")
    results = []
    for device in DEVICES:
        data = poll_device(device)
        results.append(data)
    return results


def get_down_interfaces(poll_results: list) -> list:
    """
    Extract all down interfaces across all devices.
    Returns list of dicts: { device, interface, details }
    """
    down = []
    for device_data in poll_results:
        if not device_data["reachable"]:
            continue
        for intf_name, intf_info in device_data["interfaces"].items():
            if intf_info["status"] == "down":
                down.append({
                    "device": device_data["name"],
                    "host": device_data["host"],
                    "interface": intf_name,
                    "details": intf_info
                })
    return down


# --- Run standalone to test connectivity ---
if __name__ == "__main__":
    print("=== Real AIOps Collector — Connection Test ===")
    results = poll_all_devices()

    for r in results:
        print(f"\nDevice: {r['name']}")
        if r["reachable"]:
            for intf, info in r["interfaces"].items():
                status_icon = "✅" if info["status"] == "up" else "❌"
                print(f"  {status_icon} {intf}: {info['status']}")
        else:
            print(f"  ⚠️  Not reachable: {r.get('error')}")
