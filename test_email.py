"""
Test script to verify Gmail SMTP configuration and email delivery.
"""
import smtplib
import io
from email.message import EmailMessage
from config import (
    SMTP_HOST,
    SMTP_PORT,
    SMTP_USER,
    SMTP_PASSWORD,
    SMTP_USE_TLS,
    SMTP_FROM,
    ALERT_EMAIL
)

print("=" * 60)
print("EMAIL DELIVERY TEST")
print("=" * 60)
print(f"\nConfiguration:")
print(f"  SMTP Host: {SMTP_HOST}")
print(f"  SMTP Port: {SMTP_PORT}")
print(f"  SMTP User: {SMTP_USER}")
print(f"  SMTP Use TLS: {SMTP_USE_TLS}")
print(f"  From Email: {SMTP_FROM}")
print(f"  To Email: {ALERT_EMAIL}")
print(f"\nPassword masked: {'*' * len(SMTP_PASSWORD)}")

try:
    print("\n[1] Connecting to SMTP server...")
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as smtp:
        print("    ✓ Connection successful")
        
        if SMTP_USE_TLS:
            print("[2] Starting TLS...")
            smtp.starttls()
            print("    ✓ TLS started")
        
        if SMTP_USER and SMTP_PASSWORD:
            print("[3] Authenticating...")
            smtp.login(SMTP_USER, SMTP_PASSWORD)
            print("    ✓ Authentication successful")
        
        print("[4] Creating test email...")
        msg = EmailMessage()
        msg['Subject'] = "AIOps Test Email - Gmail SMTP Verification"
        msg['From'] = SMTP_FROM
        msg['To'] = ALERT_EMAIL
        
        test_body = """This is a test email from AIOps System.

If you received this email, it means:
✓ Gmail SMTP configuration is correct
✓ Gmail authentication is working
✓ TLS connection is established
✓ Email delivery is functional

Please confirm receipt to the NOC team.

Time: Test Email
Device: Configuration Test
Status: SUCCESS

Best regards,
AIOps Test System"""
        
        msg.set_content(test_body)
        
        # Add a simple test PDF attachment
        pdf_content = b"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> >> >> >>
endobj
4 0 obj
<< /Length 44 >>
stream
BT
/F1 12 Tf
100 700 Td
(Test PDF) Tj
ET
endstream
endobj
xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000273 00000 n 
trailer
<< /Size 5 /Root 1 0 R >>
startxref
366
%%EOF
"""
        pdf_bytes = io.BytesIO(pdf_content)
        pdf_bytes.seek(0)
        msg.add_attachment(pdf_bytes.read(), maintype='application', subtype='pdf', filename='test-email.pdf')
        
        print("    ✓ Email created with test PDF")
        
        print("[5] Sending test email...")
        smtp.send_message(msg)
        print("    ✓ Email sent successfully!")
        
        print("\n" + "=" * 60)
        print("SUCCESS! Email delivery is working correctly.")
        print("=" * 60)
        print(f"\nCheck inbox at: {ALERT_EMAIL}")
        print("Subject: AIOps Test Email - Gmail SMTP Verification")

except smtplib.SMTPAuthenticationError as e:
    print(f"\n✗ AUTHENTICATION FAILED: {str(e)}")
    print("\nTroubleshooting:")
    print("  - Verify Gmail App Password is correct")
    print("  - Check if 2FA is enabled on Gmail account")
    print("  - Generate new App Password if needed")
    print("  - Ensure SENDER_EMAIL matches the Gmail account")

except smtplib.SMTPException as e:
    print(f"\n✗ SMTP ERROR: {str(e)}")
    print("\nTroubleshooting:")
    print("  - Verify SMTP host (smtp.gmail.com)")
    print("  - Verify SMTP port (587 for TLS)")
    print("  - Check internet connection")
    print("  - Try disabling firewall temporarily")

except Exception as e:
    print(f"\n✗ UNEXPECTED ERROR: {str(e)}")
    print(f"   Error type: {type(e).__name__}")

print("\n" + "=" * 60)
