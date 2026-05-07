"""
router_api.py
-------------
Flask dashboard server — serves real device data from the collector.
Same endpoints as your original router_api.py so the dashboard JS works unchanged.
"""

import io
import threading
import time
from flask import Flask, jsonify, render_template, request, send_file, make_response
from collector import poll_all_devices
from config import DEVICES, POLL_INTERVAL, DASHBOARD_PORT, OLLAMA_URL, AI_MODEL
import requests
import json
from fpdf import FPDF
from netmiko import ConnectHandler

app = Flask(__name__, template_folder='.')

# Shared state — updated by background polling thread
state = {
    "devices": [],
    "last_poll": None,
    "logs": [
        f"AIOps system started. Polling every {POLL_INTERVAL}s."
    ],
    "router_logs": []
}
state_lock = threading.Lock()


def get_default_device_host() -> str:
    """Return the first reachable device host, or first configured device."""
    # Try to find a reachable device from recent polls
    with state_lock:
        for device in state.get("devices", []):
            if device.get("reachable"):
                return device.get("host")
    
    # Fallback to first configured device
    return DEVICES[0]["host"] if DEVICES else ""


def parse_command_with_ai(command: str, device: str) -> dict:
    """Send command to Ollama to parse into structured action."""
    prompt = f"""Parse this network command into a structured action for device {device}.
Command: "{command}"

Return ONLY valid JSON in this format:
{{
  "action": "interface_up" | "interface_down" | "push_acl" | "unknown",
  "interface": "Fa0/0" (if applicable),
  "acl_src": "192.168.1.0 0.0.0.255" (if push_acl),
  "acl_dst": "192.168.2.0 0.0.0.255" (if push_acl),
  "acl_action": "deny" | "permit" (if push_acl)
}}

Examples:
- "take Fa0/0 down" -> {{"action": "interface_down", "interface": "Fa0/0"}}
- "bring Fa0/1 up" -> {{"action": "interface_up", "interface": "Fa0/1"}}
- "take f0/0 down" -> {{"action": "interface_down", "interface": "f0/0"}}
- "shutdown interface Fa0/0" -> {{"action": "interface_down", "interface": "Fa0/0"}}
- "no shutdown on Fa0/1" -> {{"action": "interface_up", "interface": "Fa0/1"}}
- "push acl from 192.168.1.0 to 192.168.2.0 deny" -> {{"action": "push_acl", "interface": "FastEthernet0/0", "acl_src": "192.168.1.0 0.0.0.255", "acl_dst": "192.168.2.0 0.0.0.255", "acl_action": "deny"}}
- "create acl deny from 192.168.1.0/24 to 192.168.2.0/24 on FastEthernet0/0" -> {{"action": "push_acl", "interface": "FastEthernet0/0", "acl_src": "192.168.1.0 0.0.0.255", "acl_dst": "192.168.2.0 0.0.0.255", "acl_action": "deny"}}
"""

    try:
        payload = {
            "model": AI_MODEL,
            "prompt": prompt,
            "stream": False,
            "format": "json"
        }
        response = requests.post(f"{OLLAMA_URL}/api/generate", json=payload, timeout=30)
        response.raise_for_status()
        raw = response.json().get("response", "").strip()
        if "```json" in raw:
            raw = raw.split("```json")[1].split("```")[0]
        parsed = json.loads(raw.strip())
        return parsed
    except Exception as e:
        # Fallback to regex parsing
        return parse_command_regex(command)


def parse_command_regex(command: str) -> dict:
    """Fallback regex-based command parsing."""
    import re

    cmd = command.lower().strip().split('\n')[0].strip()  # Take only first line

    # Interface down: take <intf> down, shutdown <intf>, etc.
    match = re.search(r'(take|shutdown)\s+(\S+)\s+down', cmd)
    if match:
        return {"action": "interface_down", "interface": match.group(2)}

    # Interface up: bring <intf> up, no shutdown <intf>, etc.
    match = re.search(r'(bring|no shutdown)\s+(\S+)\s+up', cmd)
    if match:
        return {"action": "interface_up", "interface": match.group(2)}

    # Logs retrieval: get me logs / give me logs / show logs
    match = re.search(r'\b(get|give|show)\s+(me\s+)?logs\b', cmd)
    if match:
        return {"action": "show_logs"}

    # Alias forms for IOS logging and status
    if re.search(r'\bsh(?:ow)?\s+ip\s+int(?:erface)?\s+br(?:ief)?\b', cmd) or \
       re.search(r'\baccess[- ]?lists?\b', cmd) or \
       re.search(r'\bssh\b', cmd) or \
       re.search(r'\btraffic\b', cmd):
        return {"action": "show_logs"}

    # ACL: push acl from <src> to <dst> <action> [on <intf>]
    match = re.search(r'push acl from (\S+) to (\S+) (\w+)(?: on (\S+))?', cmd)
    if match:
        src, dst, action, intf = match.groups()
        intf = intf or "FastEthernet0/0"  # Default to common EVE-NG interface
        # Convert CIDR to wildcard if needed
        src_wild = cidr_to_wildcard(src)
        dst_wild = cidr_to_wildcard(dst)
        return {
            "action": "push_acl",
            "interface": intf,
            "acl_src": src_wild,
            "acl_dst": dst_wild,
            "acl_action": action
        }

    return {"action": "unknown", "error": "No matching pattern"}


def cidr_to_wildcard(ip: str) -> str:
    """Convert CIDR notation to wildcard mask, e.g., 192.168.1.0/24 -> 192.168.1.0 0.0.0.255"""
    if '/' in ip:
        parts = ip.split('/')
        base = parts[0]
        mask = int(parts[1])
        wildcard_parts = []
        for i in range(4):
            if mask >= 8:
                wildcard_parts.append('0')
                mask -= 8
            elif mask > 0:
                wildcard_parts.append(str(256 - (1 << (8 - mask))))
                mask = 0
            else:
                wildcard_parts.append('255')
        wildcard = '.'.join(wildcard_parts)
        return f"{base} {wildcard}"
    else:
        return f"{ip} 0.0.0.0"


def generate_logs_pdf(log_lines: list[str], title: str = "AIOps Device Logs") -> io.BytesIO:
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Courier", size=9)
    
    # Title
    pdf.set_font("Courier", 'B', 12)
    pdf.cell(0, 10, title, ln=True, align='C')
    pdf.set_font("Courier", size=9)
    pdf.ln(5)
    
    # Content - handle both strings and lines
    full_text = ""
    if isinstance(log_lines, list):
        full_text = "\n".join(log_lines)
    else:
        full_text = str(log_lines)
    
    # Split by lines and add to PDF
    for line in full_text.split("\n"):
        if not line.strip():
            pdf.ln(2)
            continue
        if line.startswith("=== ") and line.endswith(" ==="):
            heading = line[4:-4].strip()
            pdf.set_font("Courier", 'B', 11)
            pdf.cell(0, 6, heading, ln=True)
            pdf.set_font("Courier", size=9)
            pdf.ln(1)
            continue
        # Truncate long lines to fit PDF width
        if len(line) > 120:
            line = line[:117] + "..."
        pdf.multi_cell(0, 5, line, border=0)
    
    pdf_output = pdf.output(dest='S').encode('latin-1')
    pdf_bytes = io.BytesIO(pdf_output)
    pdf_bytes.seek(0)
    return pdf_bytes


def execute_action(device_config: dict, action: dict) -> str:
    """Execute the parsed action on the device."""
    
    if action["action"] == "show_logs":
        # Fetch actual router logs from Cisco IOS device
        try:
            conn = ConnectHandler(**{k: v for k, v in device_config.items() if k != "name"})
            conn.enable()
            
            # Commands compatible with Cisco IOS 3725
            log_commands = [
                "show logging",
                "show history",
                "show version",
                "show ip int brief",
                "show interfaces status",
                "show access-lists",
                "show ip ssh",
                "show ip traffic"
            ]
            router_logs = []
            for cmd in log_commands:
                try:
                    output = conn.send_command(cmd, delay_factor=2)
                    if output and output.strip():
                        router_logs.append(f"=== {cmd} ===\n{output}\n")
                except Exception as e:
                    router_logs.append(f"=== {cmd} ===\nCommand failed: {str(e)}\n")
            
            conn.disconnect()
            
            if not router_logs or all('Command failed' in log for log in router_logs):
                # If all commands failed, add a message
                router_logs.insert(0, f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Note: Some or all commands could not be executed.\n")
            
            # Store router logs in state for PDF download
            with state_lock:
                state["router_logs"] = router_logs
            
            return f"[OK] Router logs retrieved from {device_config['name']}. Downloading PDF..."
        
        except Exception as e:
            error_msg = f"[CONNECTION ERROR] Failed to connect to {device_config['name']} ({device_config['host']}): {str(e)}"
            with state_lock:
                state["router_logs"] = [error_msg]
            return error_msg
    
    try:
        conn = ConnectHandler(**{k: v for k, v in device_config.items() if k != "name"})
        conn.enable()

        if action["action"] == "interface_up":
            commands = [
                f"interface {action['interface']}",
                "no shutdown"
            ]
            output = conn.send_config_set(commands)
            result = f"Interface {action['interface']} brought up."
        elif action["action"] == "interface_down":
            commands = [
                f"interface {action['interface']}",
                "shutdown"
            ]
            output = conn.send_config_set(commands)
            result = f"Interface {action['interface']} shut down."
        elif action["action"] == "push_acl":
            # Generate ACL
            acl_num = 101  # Simple, use fixed for now
            src = action.get("acl_src", "any")
            dst = action.get("acl_dst", "any")
            acl_act = action.get("acl_action", "deny")
            intf = action.get("interface", "FastEthernet0/0")  # Default to common EVE-NG interface

            def format_acl_addr(addr: str) -> str:
                if addr == "any":
                    return "any"
                parts = addr.split()
                if len(parts) == 2 and parts[1] == "0.0.0.0":
                    return f"host {parts[0]}"
                return addr

            src_formatted = format_acl_addr(src)
            dst_formatted = format_acl_addr(dst)

            commands = [
                f"access-list {acl_num} {acl_act} ip {src_formatted} {dst_formatted}",
                f"interface {intf}",
                f"ip access-group {acl_num} in"
            ]
            print(f"Debug: Sending commands to {device_config['host']}: {commands}")
            output = conn.send_config_set(commands, cmd_verify=False, delay_factor=2, max_loops=200)
            print(f"Debug: Output from device: {output}")
            if "Invalid input" in output or "% Invalid" in output:
                result = f"ACL push failed: {output.strip()}"
            else:
                result = f"ACL pushed: {acl_act} from {src_formatted} to {dst_formatted} on {intf}."
        else:
            result = "Unknown action."

        conn.save_config()
        conn.disconnect()
        return result
    except Exception as e:
        return f"Execution failed: {str(e)}"


def get_device_config(host: str) -> dict | None:
    """Look up device credentials by IP."""
    from config import DEVICES
    for d in DEVICES:
        if d["host"] == host:
            return d
    return None


def background_poller():
    """Runs in a background thread, continuously polls devices."""
    while True:
        results = poll_all_devices()
        with state_lock:
            state["devices"] = results
            state["last_poll"] = time.strftime("%Y-%m-%d %H:%M:%S")
            # Add log entries for any down interfaces
            for device in results:
                if device.get("reachable"):
                    for intf, info in device["interfaces"].items():
                        if info["status"] == "down":
                            msg = f"{state['last_poll']} CRITICAL: {device['name']} / {intf} is DOWN"
                            if msg not in state["logs"]:
                                state["logs"].append(msg)
                else:
                    msg = f"{state['last_poll']} WARNING: {device['name']} unreachable"
                    state["logs"].append(msg)
            # Keep log to last 100 lines
            state["logs"] = state["logs"][-100:]
        time.sleep(POLL_INTERVAL)


@app.route("/")
def dashboard():
    return render_template("dashboard.html", devices=DEVICES)


@app.route("/get-config")
def get_config():
    """
    Return data in the same format as your original mock router_api.py
    so the dashboard JS works without changes.
    """
    with state_lock:
        devices = state["devices"]

    if not devices:
        return jsonify({
            "hostname": "Polling...",
            "interfaces": {},
            "firewall": {"policies": []},
            "last_poll": state["last_poll"]
        })

    # Use first reachable device as primary (extend this for multi-device later)
    primary = next((d for d in devices if d.get("reachable")), devices[0])

    return jsonify({
        "hostname": primary.get("hostname", primary["name"]),
        "interfaces": primary.get("interfaces", {}),
        "acls": primary.get("acls", {}),
        "firewall": {"policies": []},  # Firewall excluded for now (per your request)
        "last_poll": state["last_poll"],
        "all_devices": [
            {
                "name": d["name"],
                "host": d["host"],
                "reachable": d.get("reachable", False),
                "interface_count": len(d.get("interfaces", {}))
            }
            for d in devices
        ]
    })


@app.route("/get-logs")
def get_logs():
    with state_lock:
        return "\n".join(state["logs"])


@app.route("/download-logs-pdf")
def download_logs_pdf():
    with state_lock:
        log_lines = state.get("router_logs", [])
    
    if not log_lines:
        log_lines = ["No router logs available. Run 'get me logs' first."]
    
    pdf_bytes = generate_logs_pdf(log_lines, title="Router Logs Export")
    return send_file(
        pdf_bytes,
        mimetype='application/pdf',
        as_attachment=True,
        download_name='router-logs.pdf'
    )


@app.route("/run-ai", methods=["POST"])
def run_ai():
    """Trigger one AI agent cycle (import inline to avoid circular imports)."""
    from ai_agent import run_ai_cycle
    try:
        run_ai_cycle()
        return jsonify({"message": "AI agent cycle complete. Check logs."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/execute-command", methods=["POST"])
def execute_command():
    """Execute a natural language command on a device."""
    data = request.get_json()
    command = data.get("command", "").strip()
    device_host = data.get("device") or get_default_device_host()

    if not command:
        return jsonify({"error": "No command provided"}), 400

    device_config = get_device_config(device_host)
    if not device_config:
        return jsonify({"error": f"Device {device_host} not found"}), 404

    # Parse command with AI
    parsed = parse_command_with_ai(command, device_config["name"])
    if parsed.get("action") == "unknown":
        return jsonify({"error": "Could not parse command", "details": parsed}), 400

    # Execute action
    result = execute_action(device_config, parsed)

    # Log the action
    with state_lock:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        state["logs"].append(f"{timestamp} MANUAL: {command} -> {result}")

    response_data = {"message": result, "parsed": parsed}
    if parsed.get("action") == "show_logs":
        response_data["download_url"] = "/download-logs-pdf"

    return jsonify(response_data)


if __name__ == "__main__":
    print("=== Real AIOps Dashboard ===")
    print(f"Starting background device poller...")

    # Start background polling thread
    poller = threading.Thread(target=background_poller, daemon=True)
    poller.start()

    print(f"Dashboard running at http://localhost:{DASHBOARD_PORT}")
    print(f"Make sure your devices in config.py are reachable before polling starts.\n")

    app.run(port=DASHBOARD_PORT, debug=False)
