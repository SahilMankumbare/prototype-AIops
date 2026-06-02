import json
import time
import os
import requests
from collector import poll_all_devices, get_down_interfaces
from remediation import fix_interface
from config import POLL_INTERVAL, OLLAMA_URL, AI_MODEL
from ai_core import (
    trend_tracker,
    AIAnalyzer,
    NetworkTrendTracker,
    extract_json,
)


def build_prompt(poll_results: list, down_interfaces: list) -> str:
    """Build a deep analysis prompt with context awareness and pattern recognition."""
    summary = []
    for device in poll_results:
        if device["reachable"]:
            up_count = sum(1 for i in device["interfaces"].values() if i["status"] == "up")
            down_count = sum(1 for i in device["interfaces"].values() if i["status"] == "down")
            summary.append(
                f"- {device['name']} ({device['host']}): "
                f"{up_count} interfaces UP, {down_count} interfaces DOWN"
            )
            for name, info in device["interfaces"].items():
                if info["status"] == "down":
                    summary.append(f"    ↓ {name}: link={info.get('link')}, proto={info.get('protocol')}")
        else:
            summary.append(f"- {device['name']} ({device['host']}): UNREACHABLE - {device.get('error')}")

    down_detail = []
    for d in down_interfaces:
        history = trend_tracker.get_interface_history(d["device"], d["interface"])
        hist_str = " | ".join([f"{h['time']}={h['status']}" for h in history[-5:]]) if history else "no history"
        down_detail.append(
            f"  - {d['device']} / {d['interface']} "
            f"(link: {d['details']['link']}, protocol: {d['details']['protocol']})"
            f"\n    Recent history: {hist_str}"
        )

    flapping = trend_tracker.get_flapping_interfaces()
    flapping_str = ""
    if flapping:
        flapping_str = "\nF LAPPING INTERFACES:\n"
        for f in flapping:
            flapping_str += f"  ⚠ {f['device']}/{f['interface']}: {f['changes']} state changes\n"

    trend_info = trend_tracker.get_trend_summary()

    prompt = f"""You are a senior network operations AI with deep analysis capability.

CURRENT NETWORK STATE:
{chr(10).join(summary)}

DOWN INTERFACES:
{chr(10).join(down_detail) if down_detail else "  None - all interfaces healthy."}
{flapping_str}

TREND ANALYSIS:
{trend_info}

Your job is to deeply analyze this network state:

1. PATTERN RECOGNITION: Are the down interfaces isolated or part of a pattern?
   - Single interface down = likely port/cable issue
   - Multiple interfaces on same device down = possible line card/module issue
   - Device unreachable = possible power/network connectivity issue
   - Multiple devices affected = possible upstream switch/routing failure

2. For EACH down interface, decide with confidence:
   - AUTO-FIX if: single interface, transient pattern, administratively down, or flapping
   - ESCALATE if: device is unreachable, multiple interfaces on same device, pattern suggests hardware failure
   - INVESTIGATE if: unclear, needs human to check further

3. Consider the history and trends in your decision.

Return ONLY valid JSON in this format:
{{
  "summary": "One sentence describing the overall situation.",
  "actions": [
    {{
      "device": "device name",
      "host": "IP address",
      "interface": "interface name",
      "decision": "AUTO-FIX" | "ESCALATE" | "INVESTIGATE",
      "reason": "detailed clinical reason based on patterns and history"
    }}
  ],
  "overall_status": "HEALTHY" | "WARNING" | "CRITICAL",
  "insight": "deeper insight about patterns or root causes observed",
  "predictive_note": "any concerns about future stability based on trends"
}}
"""
    return prompt


def run_ai_cycle():
    print("\n" + "=" * 60)
    print("AI AGENT: Starting observation cycle (Deep Analysis Mode)")

    poll_results = poll_all_devices()
    trend_tracker.record(poll_results)
    down_interfaces = get_down_interfaces(poll_results)

    print(f"AI AGENT: Sending data to {AI_MODEL} (via Ollama) for deep analysis...")
    prompt = build_prompt(poll_results, down_interfaces)

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
        decision = {
            "summary": parsed.get("summary", "No summary provided."),
            "actions": parsed.get("actions", []),
            "overall_status": parsed.get("overall_status", "UNKNOWN"),
            "insight": parsed.get("insight", ""),
            "predictive_note": parsed.get("predictive_note", "")
        }
    except requests.exceptions.ConnectionError:
        print(f"❌ ERROR: Cannot connect to Ollama at {OLLAMA_URL}. Is Ollama running?")
        return
    except Exception as e:
        print(f"❌ AI returned invalid format: {e}")
        print(f"Raw output: {raw}")
        return

    print(f"\n{'=' * 40}")
    print(f"AI ANALYSIS: {decision['summary']}")
    print(f"OVERALL STATUS: {decision['overall_status']}")
    if decision.get("insight"):
        print(f"INSIGHT: {decision['insight']}")
    if decision.get("predictive_note"):
        print(f"PREDICTIVE: {decision['predictive_note']}")

    if not decision.get("actions"):
        print("✅ No actions needed.")
        return

    for action in decision["actions"]:
        if action["decision"] == "AUTO-FIX":
            print(f"  🔧 AUTO-FIX: {action['device']}/{action['interface']} - {action.get('reason', '')}")
            success = fix_interface(action["host"], action["interface"])
            print(f"  {'✅ Fix applied' if success else '❌ Fix failed'}")
        elif action["decision"] == "INVESTIGATE":
            print(f"  🔍 INVESTIGATE: {action['device']}/{action['interface']} - {action.get('reason', '')}")
        else:
            print(f"  🚨 ESCALATE: {action['device']}/{action['interface']} - {action.get('reason', '')}")


def run_loop():
    print(f"=== Real AIOps Agent — Deep Intelligence Mode (Model: {AI_MODEL}) ===")
    while True:
        try:
            run_ai_cycle()
            time.sleep(POLL_INTERVAL)
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"❌ Agent error: {e}")
            time.sleep(10)


if __name__ == "__main__":
    run_loop()