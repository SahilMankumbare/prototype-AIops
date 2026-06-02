"""
Comprehensive test for logs command and email delivery
"""
import sys
import io
import time
from config import DEVICES, ALERT_EMAIL, SMTP_FROM
from router_api import (
    parse_command_with_ai,
    parse_command_regex,
    execute_action,
    send_email_with_attachment,
    generate_logs_pdf
)

print("=" * 70)
print("LOGS EMAIL DELIVERY DIAGNOSTIC TEST")
print("=" * 70)

# Test 1: Parse "get me logs" command
print("\n[TEST 1] Testing command parsing...")
print("-" * 70)

commands_to_test = [
    "get me logs",
    "show logs",
    "give me logs"
]

for cmd in commands_to_test:
    print(f"\nParsing: '{cmd}'")
    
    # Try regex first
    regex_result = parse_command_regex(cmd)
    print(f"  Regex parser: {regex_result}")
    
    # Try AI parser
    try:
        ai_result = parse_command_with_ai(cmd, "R1")
        print(f"  AI parser:    {ai_result}")
        
        if ai_result.get("action") == "show_logs":
            print(f"  ✓ PASS - Recognized as show_logs")
        else:
            print(f"  ✗ FAIL - Not recognized as show_logs, got: {ai_result.get('action')}")
    except Exception as e:
        print(f"  AI parser ERROR: {str(e)}")

# Test 2: Get device config
print("\n\n[TEST 2] Checking device configuration...")
print("-" * 70)
print(f"Configured devices: {[d['name'] for d in DEVICES]}")
for device in DEVICES:
    print(f"\nDevice: {device['name']}")
    print(f"  Host: {device['host']}")
    print(f"  Device Type: {device['device_type']}")

# Test 3: Email configuration
print("\n\n[TEST 3] Checking email configuration...")
print("-" * 70)
print(f"ALERT_EMAIL: {ALERT_EMAIL}")
print(f"SMTP_FROM: {SMTP_FROM}")

# Test 4: Test email with sample PDF
print("\n\n[TEST 4] Testing email delivery with sample PDF...")
print("-" * 70)

try:
    sample_logs = [
        "=== show logging ===",
        "Syslog logging: enabled (0 messages dropped, 0 flushes, 0 overruns)",
        "Console logging: level debugging",
        "",
        "=== show version ===",
        "Cisco IOS Software",
        "Version 12.4(15)T14",
        ""
    ]
    
    print("Generating test PDF...")
    pdf_bytes = generate_logs_pdf(sample_logs, title="Test Router Logs")
    print(f"✓ PDF generated: {pdf_bytes.getbuffer().nbytes} bytes")
    
    print(f"\nSending test email to {ALERT_EMAIL}...")
    result = send_email_with_attachment(
        ALERT_EMAIL,
        f"AIOps Test - Logs Email Delivery",
        f"""This is a test email for logs delivery.

Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}
Device: R1
Status: Testing

If you received this, email delivery is working!
""",
        pdf_bytes,
        f"test-logs-{time.strftime('%Y%m%d-%H%M%S')}.pdf"
    )
    print(f"Result: {result}")
    
except Exception as e:
    print(f"ERROR: {str(e)}")
    import traceback
    traceback.print_exc()

print("\n" + "=" * 70)
print("DIAGNOSTIC TEST COMPLETE")
print("=" * 70)
print("\nNext step: Run 'get me logs' command in dashboard and check logs panel")
print("for detailed execution trace and email delivery status.")
