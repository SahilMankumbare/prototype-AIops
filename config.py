# config.py — Edit this with your actual EVE-NG device details
import os

DEVICES = [
    {
        "name": "R1",
        "host": "192.168.1.8",       # Router management IP
        "device_type": "cisco_ios",
        "username": "admin",
        "password": "mypassword",
        "secret": "mypassword",
        "timeout": 60,                # Increased timeout for lab environments
    },
    {
        "name": "SW1",
        "host": "192.168.1.10",      # Switch management IP
        "device_type": "cisco_ios",
        "username": "admin",
        "password": "mypassword",
        "secret": "mypassword",
        "timeout": 60,
    }
]

# SNMP settings (if you prefer SNMP polling over SSH for interface status)
SNMP_COMMUNITY = "public"
SNMP_PORT = 161

# How often to poll (seconds)
POLL_INTERVAL = 30

# How often to check config drift (seconds)
DRIFT_CHECK_INTERVAL = 120

# Flask dashboard port
DASHBOARD_PORT = int(os.getenv("DASHBOARD_PORT", "5001"))

# ─── Email/Alert Settings ──────────────────────────────────────────────
# WARNING: Storing passwords in code is insecure for production.
# Use environment variables or a .env file instead.
# Example: set SENDER_EMAIL=you@gmail.com && set SENDER_PASSWORD=app-password
ALERT_EMAIL = "noc.engg.team@gmail.com"
NOC_EMAIL = "noc.engg.team@gmail.com"
SENDER_EMAIL = os.getenv("SENDER_EMAIL", "shaggi8536@gmail.com")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD", "dihs zmvr ohni kwyj")

# Email/SMTP settings for notification delivery (Gmail)
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = SENDER_EMAIL
SMTP_PASSWORD = SENDER_PASSWORD
SMTP_USE_TLS = True
SMTP_FROM = SENDER_EMAIL

# ─── AI Provider Settings (Local Ollama) ──────────────────────────────
# REQUIRED: Install Ollama from https://ollama.com
# Then pull the model:  ollama pull phi3
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
AI_MODEL = os.getenv("AI_MODEL", "phi3")
# 4. mistral:7b   — excellent, ~4.1GB
#
# Set with:  set AI_MODEL=phi3
