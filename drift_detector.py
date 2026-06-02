"""
drift_detector.py
-----------------
Full configuration drift detection system.
Snapshots running-config from devices, diffs against golden baseline,
classifies changes with AI, and supports rollback.

Usage:
  python drift_detector.py --snapshot    Save golden config from all devices
  python drift_detector.py --check       Check all devices for config drift
  python drift_detector.py --check --device R1   Check specific device only
"""

import json
import os
import sys
import time
import difflib
import argparse
from datetime import datetime
import requests
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
from config import DEVICES, OLLAMA_URL, AI_MODEL
from ai_core import extract_json


GOLDEN_DIR = "golden_configs"


def ensure_golden_dir():
    """Create golden configs directory if it doesn't exist."""
    os.makedirs(GOLDEN_DIR, exist_ok=True)


def golden_path(device_name: str) -> str:
    """Path to golden config file for a device."""
    return os.path.join(GOLDEN_DIR, f"{device_name}_golden.txt")


def snapshot_config(device_config: dict) -> tuple[bool, str]:
    """SSH into device, fetch running-config, save as golden baseline."""
    name = device_config["name"]
    print(f"  Snapshotting {name} ({device_config['host']})...")
    try:
        conn = ConnectHandler(**{k: v for k, v in device_config.items() if k != "name"})
        conn.enable()
        config = conn.send_command("show running-config", delay_factor=2)
        conn.disconnect()

        path = golden_path(name)
        with open(path, "w") as f:
            f.write(config)
        print(f"  [OK] Golden config saved to {path} ({len(config)} chars)")
        return True, config
    except NetmikoTimeoutException:
        return False, f"Timeout connecting to {name} ({device_config['host']})"
    except NetmikoAuthenticationException:
        return False, f"Authentication failed for {name}"
    except Exception as e:
        return False, f"Error: {str(e)}"


def fetch_current_config(device_config: dict) -> tuple[bool, str]:
    """SSH into device and fetch current running-config."""
    name = device_config["name"]
    try:
        conn = ConnectHandler(**{k: v for k, v in device_config.items() if k != "name"})
        conn.enable()
        config = conn.send_command("show running-config", delay_factor=2)
        conn.disconnect()
        return True, config
    except Exception as e:
        return False, f"Failed to fetch config from {name}: {str(e)}"


def load_golden_config(device_name: str) -> str | None:
    """Load golden config from file. Returns None if not found."""
    path = golden_path(device_name)
    if not os.path.exists(path):
        return None
    with open(path, "r") as f:
        return f.read()


def generate_diff(golden: str, current: str) -> str:
    """Generate unified diff between golden and current config."""
    golden_lines = golden.splitlines(keepends=True)
    current_lines = current.splitlines(keepends=True)
    diff = difflib.unified_diff(
        golden_lines, current_lines,
        fromfile="golden_config",
        tofile="current_config",
        n=3
    )
    return "".join(diff)


def classify_drift_with_ai(diff_text: str, device_name: str) -> dict:
    """Send the diff to Ollama to classify changes with detailed analysis."""

    if not diff_text.strip():
        return {"classification": "NO_DRIFT", "summary": "No changes detected.", "risky": False, "rollback_commands": []}

    prompt = f"""You are a Cisco network security AI analyzing configuration drift.

Device: {device_name}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

CONFIGURATION DIFF (changes from golden baseline):
{diff_text}

Analyze each change and classify the overall drift:

BENIGN = Safe changes (description updates, comments, harmless additions)
RISKY = Changes that should be reviewed (ACL changes, routing changes, interface changes)
CRITICAL = Dangerous changes (security policy removal, credential changes, unauthorized access)

Return ONLY valid JSON:
{{
  "classification": "BENIGN" | "RISKY" | "CRITICAL" | "NO_DRIFT",
  "summary": "Short explanation of what changed and why it matters.",
  "risky": true/false,
  "risk_reason": "Detailed explanation of the risk if classified as RISKY or CRITICAL",
  "rollback_commands": ["command 1", "command 2"],
  "changed_lines": ["line1", "line2"],
  "impact": "What services or features are affected by these changes"
}}"""

    raw = ""
    try:
        payload = {
            "model": AI_MODEL,
            "prompt": prompt,
            "stream": False,
            "format": "json"
        }
        response = requests.post(f"{OLLAMA_URL}/api/generate", json=payload, timeout=60)
        response.raise_for_status()
        raw = response.json().get("response", "").strip()

        parsed = extract_json(raw) or {}

        return {
            "classification": parsed.get("classification", "ERROR"),
            "summary":        parsed.get("summary", "No summary."),
            "risky":          parsed.get("risky", False),
            "risk_reason":    parsed.get("risk_reason", ""),
            "rollback_commands": parsed.get("rollback_commands", []),
            "changed_lines":  parsed.get("changed_lines", []),
            "impact":         parsed.get("impact", "")
        }
    except requests.exceptions.Timeout:
        return {"classification": "ERROR", "summary": "AI analysis timed out.", "risky": True, "rollback_commands": []}
    except requests.exceptions.ConnectionError:
        return {"classification": "ERROR", "summary": f"Cannot reach Ollama at {OLLAMA_URL}. Is it running?", "risky": True, "rollback_commands": []}
    except Exception as e:
        return {"classification": "ERROR", "summary": f"AI error: {str(e)}", "risky": True, "rollback_commands": []}


def rollback_config(device_config: dict, commands: list[str]) -> tuple[bool, str]:
    """Push rollback commands to a device."""
    if not commands:
        return False, "No rollback commands provided."
    from remediation import push_commands
    success, output = push_commands(device_config["host"], commands)
    return success, output


def check_device(device_config: dict) -> dict:
    """Check a single device for config drift. Returns full report."""
    name = device_config["name"]
    print(f"\n  Checking {name} ({device_config['host']})...")

    golden = load_golden_config(name)
    if golden is None:
        return {
            "device": name,
            "status": "NO_GOLDEN",
            "summary": f"No golden config found for {name}. Run --snapshot first.",
            "diff": "",
            "classification": None
        }

    success, current = fetch_current_config(device_config)
    if not success:
        return {"device": name, "status": "FETCH_ERROR", "summary": current, "diff": "", "classification": None}

    diff = generate_diff(golden, current)
    if not diff.strip():
        return {
            "device": name,
            "status": "CLEAN",
            "summary": f"✅ {name}: No config drift detected. Configuration matches golden baseline.",
            "diff": "",
            "classification": "NO_DRIFT"
        }

    print(f"  Diff detected ({len(diff)} chars). Sending to AI for classification...")
    analysis = classify_drift_with_ai(diff, name)

    return {
        "device": name,
        "status": "DRIFT_DETECTED",
        "summary": analysis.get("summary", "Drift detected."),
        "diff": diff,
        "classification": analysis.get("classification", "UNKNOWN"),
        "risky": analysis.get("risky", True),
        "risk_reason": analysis.get("risk_reason", ""),
        "rollback_commands": analysis.get("rollback_commands", []),
        "impact": analysis.get("impact", ""),
        "changed_lines": analysis.get("changed_lines", [])
    }


def print_report(results: list[dict]):
    """Print a formatted drift check report."""
    print("\n" + "=" * 65)
    print("  CONFIGURATION DRIFT REPORT")
    print("=" * 65)

    for r in results:
        status = r["status"]
        device = r["device"]

        if status == "NO_GOLDEN":
            print(f"\n  ⚠️  {device}: No golden baseline — run --snapshot")
            continue
        if status == "FETCH_ERROR":
            print(f"\n  ❌ {device}: {r['summary']}")
            continue
        if status == "CLEAN":
            print(f"\n  ✅ {device}: No drift")
            continue

        classification = r.get("classification", "UNKNOWN")
        cls_icon = "🔴" if classification == "CRITICAL" else ("🟡" if classification == "RISKY" else "🟢")

        print(f"\n  {cls_icon} {device}: {classification}")
        print(f"     {r['summary']}")
        if r.get("risk_reason"):
            print(f"     Risk: {r['risk_reason']}")
        if r.get("impact"):
            print(f"     Impact: {r['impact']}")
        if r.get("rollback_commands"):
            print(f"     Rollback commands: {r['rollback_commands']}")
        print(f"     Diff:")
        for line in r.get("diff", "").split("\n")[:20]:
            if line.strip():
                print(f"       {line}")
        if len(r.get("diff", "").split("\n")) > 20:
            print(f"       ... ({len(r['diff'].split(chr(10)))} diff lines total)")

    print("=" * 65)


def main():
    parser = argparse.ArgumentParser(description="Cisco Config Drift Detector with AI Classification")
    parser.add_argument("--snapshot", action="store_true", help="Save golden configs from all devices")
    parser.add_argument("--check", action="store_true", help="Check all devices for config drift")
    parser.add_argument("--device", type=str, help="Specific device name to check (optional)")
    parser.add_argument("--rollback", type=str, help="Rollback a specific device by name")
    args = parser.parse_args()

    if not any(vars(args).values()):
        parser.print_help()
        print("\nExample: python drift_detector.py --snapshot")
        print("Example: python drift_detector.py --check")
        print("Example: python drift_detector.py --check --device R1")
        return

    ensure_golden_dir()

    if args.snapshot:
        print("=== Taking Golden Config Snapshots ===\n")
        for device in DEVICES:
            success, result = snapshot_config(device)
            if not success:
                print(f"  [FAIL] {device['name']}: {result}")
        print("\nDone. Golden configs saved to ./golden_configs/")

    if args.check:
        print("=== Checking for Configuration Drift ===\n")
        targets = [d for d in DEVICES if not args.device or d["name"] == args.device]
        if not targets:
            print(f"Device '{args.device}' not found in config.py")
            return

        results = []
        for device in targets:
            result = check_device(device)
            results.append(result)

        print_report(results)

    if args.rollback:
        print(f"\n=== Rolling Back {args.rollback} ===\n")
        device = next((d for d in DEVICES if d["name"] == args.rollback), None)
        if not device:
            print(f"Device '{args.rollback}' not found.")
            return
        golden = load_golden_config(args.rollback)
        if golden is None:
            print(f"No golden config for {args.rollback}.")
            return
        success, current = fetch_current_config(device)
        if not success:
            print(f"Failed to fetch config: {current}")
            return
        diff = generate_diff(golden, current)
        analysis = classify_drift_with_ai(diff, args.rollback)
        cmds = analysis.get("rollback_commands", [])
        if not cmds:
            print("AI did not suggest rollback commands. Manual review needed.")
            return
        print(f"Suggested rollback commands: {cmds}")
        confirm = input("Push these commands? (y/N): ")
        if confirm.lower() == "y":
            succ, out = rollback_config(device, cmds)
            print(f"{'Success' if succ else 'Failed'}: {out[:500]}")
        else:
            print("Rollback cancelled.")


if __name__ == "__main__":
    main()
