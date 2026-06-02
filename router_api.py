"""
router_api.py
-------------
Flask dashboard server — serves real device data from the collector.
Same endpoints as your original router_api.py so the dashboard JS works unchanged.
"""

import io
import re
import smtplib
import threading
import time
from datetime import datetime
from email.message import EmailMessage
from flask import Flask, jsonify, render_template, request, send_file, make_response
from collector import poll_all_devices
from config import (
    DEVICES,
    POLL_INTERVAL,
    DASHBOARD_PORT,
    OLLAMA_URL,
    AI_MODEL,
    ALERT_EMAIL,
    SMTP_HOST,
    SMTP_PORT,
    SMTP_USER,
    SMTP_PASSWORD,
    SMTP_USE_TLS,
    SMTP_FROM,
)
import requests
import json
import traceback
from fpdf import FPDF
from netmiko import ConnectHandler
from ai_core import (
    chat_memory,
    trend_tracker,
    ai_insights,
    AIAnalyzer,
    extract_json,
)

app = Flask(__name__, template_folder='.')

INTERFACE_PATTERN = re.compile(
    r"\b("
    r"(?:fastethernet|fa|f|gigabitethernet|gi|g|ethernet|eth|e|"
    r"tengigabitethernet|te|serial|se|loopback|lo|vlan)"
    r"\s*\d+(?:/\d+){0,3}(?:\.\d+)?"
    r")\b",
    re.IGNORECASE,
)

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")

INTENT_ACTIONS = {
    "chat",
    "show_status",
    "show_logs",
    "show_config",
    "show_acl",
    "show_interfaces",
    "interface_up",
    "interface_down",
    "push_acl",
    "explain",
    "recommend",
    "unknown",
}

# Shared state — updated by background polling thread
state = {
    "devices": [],
    "last_poll": None,
    "logs": [
        f"AIOps system started. Polling every {POLL_INTERVAL}s."
    ],
    "router_logs": [],
    "pending_approvals": {}
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


def _keywords_match(cmd: str, keywords: list[str]) -> bool:
    return any(re.search(r'\b' + re.escape(kw) + r'\b', cmd, re.IGNORECASE) for kw in keywords)

def _ai_action_plausible(cmd: str, action: str) -> bool:
    action_keywords = {
        "show_acl": ["acl", "access-list", "access-list", "rule"],
        "show_interfaces": ["interface", "port", "int"],
        "show_status": ["status", "health", "how", "summary", "network"],
        "show_config": ["config", "running", "startup", "settings", "configuration", "configurations"],
        "show_logs": ["log"],
        "push_acl": ["acl", "push", "add", "create", "from", "to"],
        "interface_up": ["shutdown", "no shutdown", "no shut", "bring", "up", "enable", "turn on"],
        "interface_down": ["shutdown", "shut", "disable", "down", "take down", "bring down"],
    }
    if action in ("chat", "unknown", "greeting"):
        return True
    if action in action_keywords:
        return _keywords_match(cmd, action_keywords[action])
    return False

def _infer_interface_from_cache(cmd: str, device_name: str) -> str | None:
    """If user wants to bring up/down an interface but didn't name one,
    infer from cached poll data (single down interface → bring it up)."""
    with state_lock:
        for d in state.get("devices", []):
            if d.get("name") == device_name and d.get("reachable"):
                up_intent = re.search(r'\b(no\s+shutdown|bring|enable|turn\s+on)\b', cmd, re.IGNORECASE) or \
                            re.search(r'\b(take|make|set|put)\b.*\b(up|on)\b', cmd, re.IGNORECASE)
                down_intent = re.search(r'\b(shutdown|shut|disable)\b', cmd, re.IGNORECASE) or \
                              re.search(r'\b(take|put|bring)\b.*\b(down|off)\b', cmd, re.IGNORECASE) or \
                              (re.search(r'\bdown\b', cmd) and re.search(r'\b(take|put|make|set)\b', cmd))
                ifaces = d.get("interfaces", {})
                if up_intent:
                    down_ifaces = [name for name, info in ifaces.items() if info.get("status") == "down"]
                    if len(down_ifaces) == 1:
                        return down_ifaces[0]
                if down_intent:
                    up_ifaces = [name for name, info in ifaces.items() if info.get("status") == "up"]
                    if len(up_ifaces) == 1:
                        return up_ifaces[0]
    return None


def parse_command_with_ai(command: str, device: str) -> dict:
    """Send command to Ollama to parse into structured action."""
    local_match = parse_command_regex(command)
    if local_match.get("action") != "unknown":
        return local_match

    # Check if intent is clear but interface missing — infer from cached data
    cmd = command.lower().strip()
    has_up_intent = bool(re.search(r'\b(no\s+shutdown|bring|enable|turn\s+on)\b', cmd, re.IGNORECASE)) or \
                    bool(re.search(r'\b(take|make|set|put)\b.*\b(up|on)\b', cmd, re.IGNORECASE))
    has_down_intent = bool(re.search(r'\b(shutdown|shut|disable)\b', cmd, re.IGNORECASE)) or \
                      bool(re.search(r'\b(take|put|bring)\b.*\b(down|off)\b', cmd, re.IGNORECASE)) or \
                      bool(re.search(r'\b(down)\b', cmd, re.IGNORECASE) and re.search(r'\b(take|put|make|set)\b', cmd, re.IGNORECASE))
    if (has_up_intent or has_down_intent) and not extract_interface_name(command):
        inferred = _infer_interface_from_cache(cmd, device)
        if inferred:
            action = "interface_up" if has_up_intent else "interface_down"
            return {"action": action, "interface": inferred}

    prompt = f"""You are a careful intent parser for a Cisco AIOps lab.
Classify the user's message into exactly one action.

Device: {device}
Command: "{command}"

Rules:
- Use interface_up or interface_down ONLY if the user explicitly mentions shutdown, no shutdown, bring up, take down, enable, or disable an interface.
- Use chat for general questions or greetings.
- Use unknown if unsure. DO NOT invent interface actions for general talk.

Valid actions: show_acl, show_interfaces, show_status, show_config, show_logs, interface_up, interface_down, push_acl, chat, unknown

Return ONLY this JSON:
{{"action": "selected_action", "interface": "interface_name_or_empty", "acl_src": "src_or_empty", "acl_dst": "dst_or_empty", "acl_action": "deny_or_permit", "answer": "optional_chat_reply"}}
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
        parsed = extract_json(raw)
        if not parsed:
            return parse_command_regex(command)
        parsed = validate_parsed_action(command, parsed)
        if not _ai_action_plausible(command, parsed.get("action", "")):
            return {"action": "unknown"}
        return parsed
    except Exception as e:
        return parse_command_regex(command)


def normalize_interface_name(interface: str | None) -> str:
    """Return a Cisco-friendly interface token from natural language."""
    if not interface:
        return ""
    compact = re.sub(r"\s+", "", interface.strip())
    lower = compact.lower()
    aliases = [
        ("fastethernet", "FastEthernet"),
        ("gigabitethernet", "GigabitEthernet"),
        ("tengigabitethernet", "TenGigabitEthernet"),
        ("ethernet", "Ethernet"),
        ("serial", "Serial"),
        ("loopback", "Loopback"),
        ("vlan", "Vlan"),
        ("fa", "Fa"),
        ("gi", "Gi"),
        ("te", "Te"),
        ("eth", "Eth"),
        ("se", "Se"),
        ("lo", "Lo"),
        ("f", "Fa"),
        ("g", "Gi"),
        ("e", "Eth"),
    ]
    for prefix, replacement in aliases:
        if lower.startswith(prefix):
            return replacement + compact[len(prefix):]
    return compact


def extract_interface_name(command: str) -> str:
    """Find the first real-looking interface name anywhere in a sentence."""
    match = INTERFACE_PATTERN.search(command)
    return normalize_interface_name(match.group(1)) if match else ""


def validate_parsed_action(command: str, parsed: dict) -> dict:
    """Repair or reject unsafe/partial model output before execution."""
    if not isinstance(parsed, dict):
        return {"action": "unknown", "error": "AI returned non-object output"}

    action = parsed.get("action")
    if action in {"interface_up", "interface_down"}:
        interface = extract_interface_name(command)
        if not interface:
            return {
                "action": "unknown",
                "error": "No valid interface found",
                "answer": "I will not guess an interface. Tell me the exact interface, for example Fa0/1."
            }
        parsed["interface"] = interface
    elif action == "push_acl":
        parsed["interface"] = normalize_interface_name(parsed.get("interface")) or "FastEthernet0/0"
        parsed["acl_action"] = normalize_acl_action(parsed.get("acl_action", "deny"))
    return parsed


def parse_command_regex(command: str) -> dict:
    """Fallback regex-based command parsing."""
    cmd = command.lower().strip().split('\n')[0].strip()  # Take only first line
    interface = extract_interface_name(command)

    if re.search(r'\b(hi|hello|hey|how are you|who are you|what can you do|help)\b', cmd):
        return {"action": "chat", "answer": casual_chat_answer(cmd)}

    has_no_shutdown = bool(re.search(r'\bno\s+shutdown\b', cmd))
    # Down intent: explicit shutdown/disable keywords, or take/put/bring + down
    down_intent = bool(re.search(r'\b(shutdown|shut|disable)\b', cmd)) or \
                  bool(re.search(r'\b(take|put|bring)\b.*\b(down|off)\b', cmd)) or \
                  bool(re.search(r'\b(down)\b', cmd) and re.search(r'\b(take|put|make|set)\b', cmd))
    if has_no_shutdown:
        down_intent = False
    if interface and down_intent:
        return {"action": "interface_down", "interface": interface}

    # Up intent: no shutdown, bring, enable, turn on, take…up, make up, set up
    up_intent = bool(re.search(
        r'\b(no\s+shutdown|bring|enable|turn\s+on)\b', cmd,
    )) or \
        bool(re.search(r'\b(take|make|set|put)\b.*\b(up|on)\b', cmd))
    if interface and up_intent and not down_intent:
        return {"action": "interface_up", "interface": interface}

    if re.search(r'\b(shutdown|shut|take|disable|bring|enable|no\s+shutdown)\b', cmd) and not interface:
        return {"action": "unknown", "error": "I need an interface name like Fa0/1"}

    if re.search(r'\b(shutdown|shut|take|disable|bring|enable|no\s+shutdown)\b', cmd) and not interface:
        return {"action": "unknown", "error": "I need an interface name like Fa0/1"}

    # Logs retrieval: get me logs / give me logs / show logs
    match = re.search(r'\b(get|give|show)\s+(me\s+)?logs\b', cmd)
    if match:
        return {"action": "show_logs"}

    if re.search(r'\b(config|configur(?:ation)?s?|running[- ]?config|settings)\b', cmd) and \
       not re.search(r'\b(push|add|create|delete|remove|change|modify|apply)\b', cmd):
        return {"action": "show_config"}

    if re.search(r'\b(status|health|summary|how.*network|what.*network)\b', cmd):
        return {"action": "show_status"}

    # Show ACLs from cached poll data (no SSH needed)
    if re.search(r'\b(show|display|list|view|get)\s+(me\s+)?.*\b(acls?|access[- ]?lists?)\b', cmd):
        return {"action": "show_acl"}
    keyword_acl = re.search(r'\b(acls?|access[- ]?lists?)\b', cmd)
    if keyword_acl and not re.search(r'(push|add|create)\b', cmd):
        return {"action": "show_acl"}

    # Show interfaces from cached poll data (no SSH needed)
    if re.search(r'\b(show|display|list|view)\s+(me\s+)?(interfaces?|ports?|int\b)\b', cmd):
        return {"action": "show_interfaces"}
    if re.search(r'\bsh(?:ow)?\s+ip\s+int(?:erface)?\s+br(?:ief)?\b', cmd):
        return {"action": "show_interfaces"}

    # Alias forms for IOS logging
    if re.search(r'\bssh\b', cmd) or \
       re.search(r'\btraffic\b', cmd):
        return {"action": "show_logs"}

    # ACL: push acl from <src> to <dst> <action> [on <intf>]
    match = re.search(r'(?:push|add|create)\s+acl\s+from\s+(\S+)\s+to\s+(\S+)\s+(\w+)(?:\s+on\s+(\S+))?', cmd)
    if match:
        src, dst, action, intf = match.groups()
        intf = intf or "FastEthernet0/0"  # Default to common EVE-NG interface
        action = normalize_acl_action(action)
        src_wild = normalize_acl_address(src)
        dst_wild = normalize_acl_address(dst)
        if action not in {"permit", "deny"} or not src_wild or not dst_wild:
            return {"action": "unknown", "error": "Invalid ACL command"}
        return {
            "action": "push_acl",
            "interface": normalize_interface_name(intf),
            "acl_src": src_wild,
            "acl_dst": dst_wild,
            "acl_action": action
        }

    return {"action": "unknown", "error": "No matching pattern"}


def casual_chat_answer(message: str) -> str:
    """Friendly non-device responses for the dashboard copilot."""
    msg = message.lower()
    if "how are you" in msg:
        return "I am online and ready. Ask me for network status, logs, config review, interface changes, or ACL changes. I will ask for human approval before sensitive actions."
    if "who are you" in msg:
        return "I am your AI Network Copilot for this AIOps lab. I can summarize device health, fetch logs, prepare config actions, and pause risky steps for approval."
    if "what can you do" in msg or "help" in msg:
        return "Try: 'what is the network status', 'get me logs', 'show running config', 'shutdown interface Fa0/0', or 'push acl from 192.168.1.0/24 to 192.168.2.0/24 deny'."
    return "Hello. I am ready to help with your network operations."


def ask_ai_for_chat_answer(message: str) -> str:
    """Use the local model for general chat, with conversation memory and full context."""
    with state_lock:
        current_devices = list(state.get("devices", []))
        last_poll = state.get("last_poll", "never")

    network_context = f"Current network state (last polled: {last_poll}):\n"
    for device in current_devices:
        if device.get("reachable"):
            up = sum(1 for i in device["interfaces"].values() if i["status"] == "up")
            down = sum(1 for i in device["interfaces"].values() if i["status"] == "down")
            network_context += f"- {device['name']} ({device['host']}): {up} UP, {down} DOWN\n"
        else:
            network_context += f"- {device['name']} ({device['host']}): UNREACHABLE\n"

    trend_info = trend_tracker.get_trend_summary()

    history_context = chat_memory.build_context()

    prompt = f"""You are an AI Network Copilot inside a Cisco AIOps lab dashboard.
You have full visibility into the live network.

LIVE NETWORK STATE:
{network_context}

TRENDS:
{trend_info}

{history_context}

User: {message}

Provide a concise, helpful response. If the user asks about network status, use the live data above. If they want a router change, tell them it will be queued for human approval. Be conversational but professional."""
    try:
        payload = {
            "model": AI_MODEL,
            "prompt": prompt,
            "stream": False,
        }
        response = requests.post(f"{OLLAMA_URL}/api/generate", json=payload, timeout=30)
        response.raise_for_status()
        answer = response.json().get("response", "").strip()
        return answer or casual_chat_answer(message)
    except Exception:
        return casual_chat_answer(message)


def ask_ai_about_network(question: str) -> str:
    """Intelligent response about any network question.
    Uses cached poll data with AI enhancement where available.
    Falls back to clean formatted data when AI is unreliable."""

    with state_lock:
        current_devices = list(state.get("devices", []))
        last_poll = state.get("last_poll", "never")
        logs = list(state.get("logs", []))

    # Always build a clean data summary as fallback
    data_summary = f"Network state (last polled: {last_poll})\n"
    data_summary += "-" * 40 + "\n"
    for device in current_devices:
        name = device.get("name", "?")
        host = device.get("host", "?")
        if not device.get("reachable"):
            data_summary += f"\n{name} ({host}): ❌ UNREACHABLE — {device.get('error', 'no response')}\n"
            continue
        data_summary += f"\n{name} ({host}): ✅ Reachable\n"
        interfaces = device.get("interfaces", {})
        for intf_name, info in interfaces.items():
            icon = "✅" if info["status"] == "up" else "❌"
            data_summary += f"  {icon} {intf_name}: {info['status'].upper()} (link: {info.get('link', '?')}, proto: {info.get('protocol', '?')})\n"
        up = sum(1 for i in interfaces.values() if i["status"] == "up")
        down = sum(1 for i in interfaces.values() if i["status"] == "down")
        data_summary += f"  → {up} UP, {down} DOWN\n"

        acls = device.get("acls", {})
        if acls:
            data_summary += f"  📋 ACLs configured:\n"
            for num, data in acls.items():
                rules = data.get("rules", [])
                data_summary += f"     ACL {num} ({data['type']}): {len(rules)} rule(s)\n"
                for r in rules:
                    if data["type"] == "standard":
                        data_summary += f"       {r['seq']} {r['action']} {r['src']}\n"
                    else:
                        data_summary += f"       {r['seq']} {r['action']} {r.get('protocol', 'ip')} {r.get('src')} {r.get('dst')}\n"
        else:
            data_summary += f"  📋 No ACLs configured.\n"

    trend_info = trend_tracker.get_trend_summary()
    flapping = trend_tracker.get_flapping_interfaces()
    if flapping:
        data_summary += "\n⚠️ Flapping interfaces:\n"
        for f in flapping:
            data_summary += f"  {f['device']}/{f['interface']}: {f['changes']} state changes\n"

    # Check if question is asking for specific data that we can answer directly
    q = question.lower()
    asks_for_acls = any(w in q for w in ['acl', 'acls', 'access-list', 'access-lists', 'access list', 'access lists'])
    asks_for_interfaces = any(w in q for w in ['interface', 'interfaces', 'int ', 'ports'])
    asks_for_status = any(w in q for w in ['status', 'health', 'how is', 'summary', 'state'])

    # For direct data queries, answer from the data without AI
    if (asks_for_acls or asks_for_interfaces or asks_for_status) and current_devices:
        return data_summary

    # For conversation/chat, try AI with a simple prompt
    history_context = chat_memory.build_context()
    simple_prompt = f"""You are a helpful network AI assistant. Answer naturally and briefly.

Recent conversation:
{history_context}

Current time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

User: {question}

Answer conversationally and concisely. If they ask about network data, check the data below:
{data_summary}

Focus on being helpful and accurate. If you don't know, say so."""
    try:
        payload = {"model": AI_MODEL, "prompt": simple_prompt, "stream": False}
        resp = requests.post(f"{OLLAMA_URL}/api/generate", json=payload, timeout=30)
        resp.raise_for_status()
        answer = resp.json().get("response", "").strip()
        # Quality check: if AI response is too short or contains suspicious patterns, use data
        if not answer or len(answer) < 10 or "pause for human approval" in answer.lower():
            return data_summary
        return answer
    except Exception:
        return data_summary


def cidr_to_wildcard(ip: str) -> str:
    """Convert CIDR notation to wildcard mask, e.g., 192.168.1.0/24 -> 192.168.1.0 0.0.0.255"""
    if '/' in ip:
        parts = ip.split('/')
        base = parts[0]
        try:
            mask = int(parts[1])
        except ValueError:
            return f"{ip} 0.0.0.0"
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


def normalize_acl_action(action: str) -> str:
    action = action.lower().strip()
    if action == "allow":
        return "permit"
    if action in {"block", "deny", "drop"}:
        return "deny"
    return action


def normalize_acl_address(addr: str) -> str:
    addr = addr.strip().lower()
    if addr in {"any", "ip any", "any ip"}:
        return "any"
    if '/' in addr:
        return cidr_to_wildcard(addr)
    parts = addr.split('.')
    if len(parts) == 4:
        if parts[3] == '0':
            # Default bare network addresses ending in .0 to /24
            return f"{addr} 0.0.0.255"
        return f"{addr} 0.0.0.0"
    return ""


def summarize_latest_state() -> str:
    """Create a short status summary from the latest poll data."""
    with state_lock:
        devices = list(state.get("devices", []))
        last_poll = state.get("last_poll") or "not polled yet"

    if not devices:
        return "I do not have live poll data yet. Wait for the background poller or check device reachability."

    lines = [f"Latest poll: {last_poll}"]
    for device in devices:
        name = device.get("name", "device")
        host = device.get("host", "unknown")
        if not device.get("reachable"):
            lines.append(f"{name} ({host}) is unreachable: {device.get('error', 'no detail')}")
            continue
        interfaces = device.get("interfaces", {})
        up_count = sum(1 for info in interfaces.values() if info.get("status") == "up")
        down_count = sum(1 for info in interfaces.values() if info.get("status") == "down")
        lines.append(f"{name} ({host}) is reachable. {up_count} interfaces up, {down_count} down.")
    return "\n".join(lines)


def action_requires_approval(action: dict) -> bool:
    """Human approval gate for writes and sensitive reads."""
    return action.get("action") in {"interface_up", "interface_down", "push_acl", "show_config", "show_logs"}


def describe_action(action: dict, device_config: dict) -> str:
    action_name = action.get("action")
    if action_name == "interface_up":
        return f"Bring interface {action.get('interface')} up on {device_config['name']}."
    if action_name == "interface_down":
        return f"Shut interface {action.get('interface')} down on {device_config['name']}."
    if action_name == "push_acl":
        return (
            f"Apply ACL on {device_config['name']} {action.get('interface', 'FastEthernet0/0')}: "
            f"{action.get('acl_action', 'deny')} from {action.get('acl_src', 'any')} "
            f"to {action.get('acl_dst', 'any')}."
        )
    if action_name == "show_config":
        return f"Read running configuration from {device_config['name']}."
    if action_name == "show_logs":
        return f"Fetch router logs from {device_config['name']} and prepare a PDF/email report."
    return f"Run {action_name} on {device_config['name']}."


def planned_commands_for_action(action: dict) -> list[str]:
    """Show the human what will be sent before they approve."""
    action_name = action.get("action")
    if action_name == "interface_up":
        return [f"interface {action.get('interface')}", "no shutdown"]
    if action_name == "interface_down":
        return [f"interface {action.get('interface')}", "shutdown"]
    if action_name == "show_config":
        return ["show running-config"]
    if action_name == "push_acl":
        acl_num = 101
        src = action.get("acl_src", "any")
        dst = action.get("acl_dst", "any")
        acl_act = normalize_acl_action(action.get("acl_action", "deny"))
        intf = action.get("interface", "FastEthernet0/0")
        return [
            f"access-list {acl_num} {acl_act} ip {src} {dst}",
            f"interface {intf}",
            f"ip access-group {acl_num} in",
        ]
    return []


def create_pending_approval(command: str, device_host: str, action: dict) -> dict:
    device_config = get_device_config(device_host)
    approval_id = str(int(time.time() * 1000))
    approval = {
        "id": approval_id,
        "command": command,
        "device": device_host,
        "device_name": device_config["name"] if device_config else device_host,
        "action": action,
        "description": describe_action(action, device_config) if device_config else str(action),
        "commands": planned_commands_for_action(action),
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "status": "pending"
    }
    with state_lock:
        state["pending_approvals"][approval_id] = approval
        state["logs"].append(f"{approval['created_at']} APPROVAL REQUIRED: {approval['description']}")
    return approval


def build_chat_response(message: str, parsed: dict, result: str | None = None, approval: dict | None = None) -> str:
    if approval:
        return f"I prepared this action and paused for human approval: {approval['description']}"
    if parsed.get("action") == "chat":
        return parsed.get("answer", "I am ready.")
    if parsed.get("action") == "show_status":
        return summarize_latest_state()
    if parsed.get("action") == "unknown":
        return "I could not safely map that to a network action. Try asking for status, logs, config, interface up/down, or an ACL."
    return result or "Done."


def handle_natural_language_command(command: str, device_host: str, source: str = "CHAT") -> tuple[dict, int]:
    if not command:
        return {"error": "No command provided"}, 400

    device_config = get_device_config(device_host)
    if not device_config:
        return {"error": f"Device {device_host} not found"}, 404

    # Store user message in conversation memory
    chat_memory.add("user", command)

    parsed = parse_command_with_ai(command, device_config["name"])
    if not parsed.get("action"):
        parsed = {
            "action": "chat",
            "answer": parsed.get("answer") or parsed.get("summary") or casual_chat_answer(command)
        }

    if parsed.get("action") == "unknown":
        ai_reply = parsed.get("answer") or ask_ai_about_network(command)
        chat_memory.add("assistant", ai_reply)
        # Return 200 so the chat shows the AI response normally, not as an error
        return {"message": ai_reply, "reply": ai_reply, "parsed": parsed}, 200

    if parsed.get("action") == "chat":
        reply = parsed.get("answer") or ask_ai_about_network(command)
        chat_memory.add("assistant", reply)
        return {"message": reply, "reply": reply, "parsed": parsed}, 200

    if parsed.get("action") == "show_status":
        reply = ask_ai_about_network(command)
        chat_memory.add("assistant", reply)
        return {"message": reply, "reply": reply, "parsed": parsed}, 200

    if action_requires_approval(parsed):
        approval = create_pending_approval(command, device_host, parsed)
        reply = build_chat_response(command, parsed, approval=approval)
        chat_memory.add("assistant", reply)
        return {
            "message": reply,
            "reply": reply,
            "approval_required": True,
            "approval": approval,
            "parsed": parsed
        }, 202

    result = execute_action(device_config, parsed)
    with state_lock:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        state["logs"].append(f"{timestamp} {source}: {command} -> {result}")

    reply = build_chat_response(command, parsed, result=result)
    chat_memory.add("assistant", reply)

    response_data = {"message": result, "reply": reply, "parsed": parsed}
    if parsed.get("action") == "show_logs":
        response_data["download_url"] = "/download-logs-pdf"
    return response_data, 200


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


def send_email_with_attachment(to_email: str, subject: str, body: str, attachment: io.BytesIO, filename: str) -> str:
    """Send email with PDF attachment. Returns status message."""
    try:
        print(f"[EMAIL-DEBUG] Creating email message...")
        print(f"[EMAIL-DEBUG] To: {to_email}")
        print(f"[EMAIL-DEBUG] From: {SMTP_FROM}")
        print(f"[EMAIL-DEBUG] Subject: {subject}")
        print(f"[EMAIL-DEBUG] SMTP_HOST: {SMTP_HOST}")
        print(f"[EMAIL-DEBUG] SMTP_PORT: {SMTP_PORT}")
        print(f"[EMAIL-DEBUG] SMTP_USE_TLS: {SMTP_USE_TLS}")
        print(f"[EMAIL-DEBUG] SMTP_USER: {SMTP_USER}")
        print(f"[EMAIL-DEBUG] Attachment: {filename}")
        
        msg = EmailMessage()
        msg['Subject'] = subject
        msg['From'] = SMTP_FROM
        msg['To'] = to_email
        msg.set_content(body)

        attachment.seek(0)
        attachment_data = attachment.read()
        print(f"[EMAIL-DEBUG] Attachment size: {len(attachment_data)} bytes")
        msg.add_attachment(attachment_data, maintype='application', subtype='pdf', filename=filename)

        print(f"[EMAIL-DEBUG] Connecting to {SMTP_HOST}:{SMTP_PORT}...")
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as smtp:
            print(f"[EMAIL-DEBUG] Connected to SMTP server")
            if SMTP_USE_TLS:
                print(f"[EMAIL-DEBUG] Starting TLS...")
                smtp.starttls()
                print(f"[EMAIL-DEBUG] TLS started")
            if SMTP_USER and SMTP_PASSWORD:
                print(f"[EMAIL-DEBUG] Authenticating with {SMTP_USER}...")
                smtp.login(SMTP_USER, SMTP_PASSWORD)
                print(f"[EMAIL-DEBUG] Authentication successful")
            print(f"[EMAIL-DEBUG] Sending message...")
            smtp.send_message(msg)
            print(f"[EMAIL-DEBUG] Message sent successfully")
        return f"SUCCESS: Email sent to {to_email}"
    except Exception as e:
        error_msg = f"FAILED: {str(e)}"
        print(f"[EMAIL-DEBUG] ERROR: {error_msg}")
        import traceback
        traceback.print_exc()
        return error_msg


def execute_action(device_config: dict, action: dict) -> str:
    """Execute the parsed action on the device."""
    # Check device reachability from cached poll data before attempting SSH
    with state_lock:
        device_state = next(
            (d for d in state.get("devices", [])
             if d.get("name") == device_config.get("name")),
            None
        )

    ssh_actions = {"show_logs", "show_config", "interface_up", "interface_down", "push_acl"}
    if action.get("action") in ssh_actions:
        if device_state and not device_state.get("reachable", False):
            return (
                f"⚠️ {device_config['name']} is currently UNREACHABLE "
                f"(last poll: {device_state.get('error', 'no response')}). "
                f"SSH actions cannot be executed until the device is back online."
            )
    
    if action.get("action") == "show_logs":
        # Fetch actual router logs from Cisco IOS device
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"\n[DEBUG] {timestamp} - Starting show_logs action")
        print(f"[DEBUG] Device: {device_config['name']} ({device_config['host']})")
        print(f"[DEBUG] Alert Email: {ALERT_EMAIL}")
        
        try:
            print(f"[DEBUG] Connecting to {device_config['host']}...")
            conn = ConnectHandler(**{k: v for k, v in device_config.items() if k != "name"})
            conn.enable()
            print(f"[DEBUG] Connected successfully")
            
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
                    print(f"[DEBUG] Executing: {cmd}")
                    output = conn.send_command(cmd, delay_factor=2)
                    if output and output.strip():
                        router_logs.append(f"=== {cmd} ===\n{output}\n")
                        print(f"[DEBUG] Got {len(output)} chars from {cmd}")
                except Exception as e:
                    print(f"[DEBUG] Command failed: {cmd} - {str(e)}")
                    router_logs.append(f"=== {cmd} ===\nCommand failed: {str(e)}\n")
            
            conn.disconnect()
            print(f"[DEBUG] Disconnected from router")
            
            if not router_logs or all('Command failed' in log for log in router_logs):
                # If all commands failed, add a message
                router_logs.insert(0, f"[{timestamp}] Note: Some or all commands could not be executed.\n")
            
            # Store router logs in state for PDF download
            with state_lock:
                state["router_logs"] = router_logs
            print(f"[DEBUG] Stored {len(router_logs)} log entries in state")

            print(f"[DEBUG] Generating PDF...")
            pdf_bytes = generate_logs_pdf(router_logs, title=f"Router Logs Report - {device_config['name']}")
            print(f"[DEBUG] PDF generated, size: {pdf_bytes.getbuffer().nbytes} bytes")
            
            # Prepare detailed email body
            email_body = f"""AIOps System - Router Log Report

Generated: {timestamp}
Device: {device_config['name']} ({device_config['host']})

--- LOG INFORMATION ---
The attached PDF contains the following command outputs:

1. Show Logging - System logging buffer
2. Show History - Command history
3. Show Version - Router hardware and software info
4. Show IP Int Brief - Interface IP addresses
5. Show Interfaces Status - All interface status
6. Show Access-Lists - ACL configurations
7. Show IP SSH - SSH configuration details
8. Show IP Traffic - IP traffic statistics

--- DETAILS ---
Total commands executed: {len(log_commands)}
Timestamp: {timestamp}

Please review the attached PDF for detailed information.

Best regards,
AIOps Monitoring System
"""
            
            print(f"[DEBUG] Sending email to {ALERT_EMAIL}...")
            email_result = send_email_with_attachment(
                ALERT_EMAIL,
                f"AIOps Router Logs from {device_config['name']} - {timestamp}",
                email_body,
                pdf_bytes,
                f"router-logs-{device_config['name']}-{timestamp.replace(' ', '_').replace(':', '-')}.pdf"
            )
            print(f"[DEBUG] Email result: {email_result}")
            
            with state_lock:
                state["logs"].append(f"{timestamp} EMAIL: {email_result}")

            result_msg = f"[OK] Router logs retrieved from {device_config['name']}. {email_result}"
            print(f"[DEBUG] Returning: {result_msg}\n")
            return result_msg
        
        except Exception as e:
            error_msg = f"[CONNECTION ERROR] Failed to connect to {device_config['name']} ({device_config['host']}): {str(e)}"
            print(f"[DEBUG] ERROR: {error_msg}\n")
            with state_lock:
                state["router_logs"] = [error_msg]
                state["logs"].append(f"{timestamp} ERROR: {error_msg}")
            return error_msg

    if action.get("action") == "show_acl":
        with state_lock:
            devices = list(state.get("devices", []))
        target = next((d for d in devices if d.get("name") == device_config["name"] or d.get("host") == device_config["host"]), None)
        if not target or not target.get("acls"):
            return f"No ACL data available for {device_config['name']}. Wait for next poll or check device connectivity."
        acls = target["acls"]
        if not acls:
            return f"✅ {device_config['name']} has no ACLs configured."
        result = f"ACL Report for {device_config['name']}:\n"
        for num, data in acls.items():
            result += f"\nACL {num} ({data['type']}):\n"
            for rule in data.get("rules", []):
                if data["type"] == "standard":
                    result += f"  {rule['seq']} {rule['action']} {rule['src']}\n"
                else:
                    result += f"  {rule['seq']} {rule['action']} {rule.get('protocol', 'ip')} {rule.get('src', 'any')} {rule.get('dst', 'any')}\n"
        return result

    if action.get("action") == "show_interfaces":
        with state_lock:
            devices = list(state.get("devices", []))
        target = next((d for d in devices if d.get("name") == device_config["name"] or d.get("host") == device_config["host"]), None)
        if not target or not target.get("interfaces"):
            return f"No interface data available for {device_config['name']}. Wait for next poll or check device connectivity."
        ifaces = target["interfaces"]
        result = f"Interface Status for {device_config['name']}:\n"
        for name, info in ifaces.items():
            icon = "✅" if info["status"] == "up" else "❌"
            result += f"  {icon} {name}: {info['status'].upper()} (link: {info.get('link', '?')}, protocol: {info.get('protocol', '?')})\n"
        up = sum(1 for i in ifaces.values() if i["status"] == "up")
        down = sum(1 for i in ifaces.values() if i["status"] == "down")
        result += f"\nSummary: {up} UP, {down} DOWN"
        return result

    if action.get("action") == "show_config":
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        try:
            conn = ConnectHandler(**{k: v for k, v in device_config.items() if k != "name"})
            conn.enable()
            output = conn.send_command("show running-config", delay_factor=2)
            conn.disconnect()

            with state_lock:
                state["router_logs"] = [f"=== show running-config ===\n{output}\n"]
                state["logs"].append(f"{timestamp} CONFIG READ: {device_config['name']} running-config retrieved")

            preview = output[:1800]
            if len(output) > len(preview):
                preview += "\n...output truncated in chat. Use Download Logs PDF for the full captured config."
            return f"Running configuration from {device_config['name']}:\n{preview}"
        except Exception as e:
            return f"[CONNECTION ERROR] Failed to read config from {device_config['name']}: {str(e)}"
    
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
            acl_act = normalize_acl_action(action.get("acl_action", "deny"))
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
            if acl_act not in {"permit", "deny"}:
                return f"ACL push failed: invalid action '{acl_act}'. Use allow/permit or deny."

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
        # Feed data to AI intelligence layer
        trend_tracker.record(results)
        time.sleep(POLL_INTERVAL)


def ai_insights_worker():
    """Background thread that periodically runs deep AI analysis on network state."""
    while True:
        time.sleep(POLL_INTERVAL * 3)
        try:
            with state_lock:
                current_devices = list(state.get("devices", []))
            if not current_devices:
                continue
            trend_summary = trend_tracker.get_trend_summary()
            analysis = AIAnalyzer.analyze_network_health(current_devices, trend_summary)
            if analysis:
                ai_insights.update(analysis)
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                with state_lock:
                    if analysis.get("status") in ("WARNING", "CRITICAL"):
                        state["logs"].append(f"{timestamp} AI INSIGHT: {analysis.get('summary', '')}")
        except Exception as e:
            print(f"[AI-INSIGHTS] Error: {e}")


# ─── AI Intelligence Endpoints ──────────────────────────────────────────────

@app.route("/insights")
def get_insights():
    """Return AI-generated network insights and health analysis."""
    latest = ai_insights.get_latest()
    trend_summary = trend_tracker.get_trend_summary()
    flapping = trend_tracker.get_flapping_interfaces()
    return jsonify({
        "insight": latest,
        "trend_summary": trend_summary,
        "flapping_interfaces": flapping,
        "health_score": latest.get("score", 100),
        "status": latest.get("status", "UNKNOWN")
    })


@app.route("/root-cause", methods=["POST"])
def root_cause():
    """Perform AI root cause analysis for a specific interface."""
    data = request.get_json() or {}
    device = data.get("device", "")
    interface = data.get("interface", "")
    if not device or not interface:
        return jsonify({"error": "device and interface required"}), 400

    with state_lock:
        current_devices = list(state.get("devices", []))

    interface_history = trend_tracker.get_interface_history(device, interface)
    trend_summary = trend_tracker.get_trend_summary()
    analysis = AIAnalyzer.root_cause_analysis(
        device, interface, current_devices, interface_history, trend_summary
    )
    return jsonify({
        "device": device,
        "interface": interface,
        "analysis": analysis,
        "history": interface_history
    })


@app.route("/network-trends")
def network_trends():
    """Return historical trend data for dashboard visualization."""
    flapping = trend_tracker.get_flapping_interfaces()
    return jsonify({
        "flapping_interfaces": flapping,
        "trend_summary": trend_tracker.get_trend_summary()
    })


@app.route("/")
def dashboard():
    return render_template("dashboard.html", devices=DEVICES, ai_model=AI_MODEL)


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


@app.route("/pending-approvals")
def pending_approvals():
    with state_lock:
        approvals = [
            approval for approval in state["pending_approvals"].values()
            if approval.get("status") == "pending"
        ]
    return jsonify({"approvals": approvals})


@app.route("/approve-action", methods=["POST"])
def approve_action():
    data = request.get_json() or {}
    approval_id = data.get("approval_id")
    approve = bool(data.get("approve", False))

    with state_lock:
        approval = state["pending_approvals"].get(approval_id)

    if not approval:
        return jsonify({"error": "Approval request not found"}), 404
    if approval.get("status") != "pending":
        return jsonify({
            "message": f"Action already {approval.get('status')}.",
            "approval": approval
        }), 409

    if not approve:
        with state_lock:
            approval["status"] = "denied"
            state["logs"].append(f"{time.strftime('%Y-%m-%d %H:%M:%S')} DENIED: {approval['description']}")
        return jsonify({"message": "Action denied.", "approval": approval})

    device_config = get_device_config(approval["device"])
    if not device_config:
        return jsonify({"error": f"Device {approval['device']} not found"}), 404

    result = execute_action(device_config, approval["action"])
    with state_lock:
        approval["status"] = "approved"
        approval["result"] = result
        state["logs"].append(f"{time.strftime('%Y-%m-%d %H:%M:%S')} APPROVED: {approval['description']} -> {result}")

    response_data = {"message": result, "approval": approval}
    if approval["action"].get("action") == "show_config":
        response_data["download_url"] = "/download-logs-pdf"
    return jsonify(response_data)


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
    data = request.get_json() or {}
    command = data.get("command", "").strip()
    device_host = data.get("device") or get_default_device_host()

    print(f"\n[COMMAND-DEBUG] Received command: {command}")
    print(f"[COMMAND-DEBUG] Device host: {device_host}")

    response_data, status = handle_natural_language_command(command, device_host, source="MANUAL")
    print(f"[COMMAND-DEBUG] Returning response\n")
    return jsonify(response_data), status


@app.route("/chat", methods=["POST"])
def chat():
    """Chatbot endpoint with AI parsing and human approval controls."""
    data = request.get_json() or {}
    message = data.get("message", "").strip()
    device_host = data.get("device") or get_default_device_host()
    response_data, status = handle_natural_language_command(message, device_host, source="CHAT")
    return jsonify(response_data), status


if __name__ == "__main__":
    print("=== Real AIOps Dashboard ===")
    print(f"Starting background device poller...")

    # Start background polling thread
    poller = threading.Thread(target=background_poller, daemon=True)
    poller.start()

    # Start AI intelligence background analysis
    insights_worker = threading.Thread(target=ai_insights_worker, daemon=True)
    insights_worker.start()
    print("  [AI] Intelligence layer activated — proactive analysis running")

    print(f"Dashboard running at http://localhost:{DASHBOARD_PORT}")
    print(f"Make sure your devices in config.py are reachable before polling starts.\n")

    app.run(port=DASHBOARD_PORT, debug=False)
