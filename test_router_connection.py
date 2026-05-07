#!/usr/bin/env python3
"""
Test script to verify router connectivity and fetch actual logs
"""

from netmiko import ConnectHandler
from config import DEVICES

def test_device_connection(device_config):
    """Test if a device is reachable and fetch logs"""
    print(f"\n{'='*60}")
    print(f"Testing: {device_config['name']} ({device_config['host']})")
    print('='*60)
    
    try:
        print(f"[*] Connecting to {device_config['name']}...")
        conn = ConnectHandler(**{k: v for k, v in device_config.items() if k != "name"})
        conn.enable()
        print(f"[✓] Connected successfully!")
        
        # Test basic command
        print(f"[*] Running: show version")
        output = conn.send_command("show version")
        print(f"[✓] Got output ({len(output)} chars):\n{output[:200]}...\n")
        
        # Fetch logs
        log_commands = [
            "show logging",
            "show log buffer", 
            "show history"
        ]
        
        print(f"[*] Fetching logs...")
        for cmd in log_commands:
            try:
                output = conn.send_command(cmd)
                if output.strip():
                    print(f"\n[✓] {cmd}:\n{output}\n")
                else:
                    print(f"[!] {cmd}: (empty output)")
            except Exception as e:
                print(f"[!] {cmd}: Error - {str(e)}")
        
        conn.disconnect()
        print(f"[✓] Disconnected from {device_config['name']}")
        
    except Exception as e:
        print(f"[✗] Connection failed: {str(e)}")
        print(f"    Check:")
        print(f"    - IP address is correct: {device_config['host']}")
        print(f"    - Device is powered on and reachable")
        print(f"    - Username/password are correct: {device_config['username']}")
        print(f"    - SSH/Telnet port is open (default 22/23)")

if __name__ == "__main__":
    print("Router Connectivity & Log Retrieval Test\n")
    
    for device in DEVICES:
        test_device_connection(device)
    
    print(f"\n{'='*60}")
    print("Test complete. If all devices connected, 'get me logs' will work.")
    print('='*60)
