# config.py — Edit this with your actual EVE-NG device details
DEVICES = [
    {
        "name": "R1",
        "host": "192.168.1.6",       # Router management IP
        "device_type": "cisco_ios",
        "username": "admin",
        "password": "mypassword",
        "secret": "mypassword",
        "timeout": 60,                # Increased timeout for lab environments
    },
    {
        "name": "SW1",
        "host": "192.168.2.10",      # Switch management IP
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
DASHBOARD_PORT = 5001

# Alert settings (reuse from your log_analyzer.py if you want)
ALERT_EMAIL = "noc.engg.team@gmail.com"

# AI Provider Settings (Local Ollama)
OLLAMA_URL = "http://localhost:11434"
AI_MODEL = "llama3"
