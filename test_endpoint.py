"""
Test the /execute-command endpoint with "get me logs"
"""
import requests
import json
import time

BASE_URL = "http://localhost:5001"

print("=" * 70)
print("TESTING /execute-command ENDPOINT WITH 'get me logs'")
print("=" * 70)

# Wait a moment for server to be ready
print("\nWaiting for server to be ready...")
time.sleep(2)

# Test the execute-command endpoint
print(f"\nSending POST request to {BASE_URL}/execute-command")
print("Command: 'get me logs'")
print("Device: R1 (192.168.1.8)")

try:
    response = requests.post(
        f"{BASE_URL}/execute-command",
        json={
            "command": "get me logs",
            "device": "192.168.1.8"
        },
        timeout=60
    )
    
    print(f"\nResponse Status: {response.status_code}")
    print(f"Response Headers: {dict(response.headers)}")
    
    data = response.json()
    print(f"\nResponse JSON:")
    print(json.dumps(data, indent=2))
    
    if response.status_code == 200:
        print("\n✓ SUCCESS - Command executed")
        if "download_url" in data:
            print(f"✓ Download URL available: {data['download_url']}")
        if "SUCCESS" in data.get("message", ""):
            print("✓ Email sent successfully")
        elif "FAILED" in data.get("message", ""):
            print("✗ Email delivery failed - check message")
        else:
            print(f"Message: {data.get('message', 'N/A')}")
    else:
        print(f"\n✗ FAILED - Status {response.status_code}")
        
except Exception as e:
    print(f"\n✗ ERROR: {str(e)}")
    import traceback
    traceback.print_exc()

# Also check the logs endpoint
print("\n\nChecking /get-logs endpoint for status messages...")
try:
    response = requests.get(f"{BASE_URL}/get-logs", timeout=10)
    if response.status_code == 200:
        logs = response.json()
        print(f"\nSystem logs (last 10 entries):")
        for log in logs.get("logs", [])[-10:]:
            print(f"  {log}")
except Exception as e:
    print(f"Error getting logs: {str(e)}")

print("\n" + "=" * 70)
