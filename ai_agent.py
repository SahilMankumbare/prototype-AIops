import json
import time
import os
import requests
from collector import poll_all_devices, get_down_interfaces
from remediation import fix_interface
from config import POLL_INTERVAL, OLLAMA_URL, AI_MODEL


def build_prompt(poll_results: list, down_interfaces: list) -> str:
    """Build the analysis prompt for Gemini."""
    summary = []
    for device in poll_results:
        if device["reachable"]:
            up_count = sum(1 for i in device["interfaces"].values() if i["status"] == "up")
            down_count = sum(1 for i in device["interfaces"].values() if i["status"] == "down")
            summary.append(
                f"- {device['name']} ({device['host']}): "
                f"{up_count} interfaces UP, {down_count} interfaces DOWN"
            )
        else:
            summary.append(f"- {device['name']} ({device['host']}): UNREACHABLE — {device.get('error')}")

    down_detail = []
    for d in down_interfaces:
        down_detail.append(
            f"  - {d['device']} / {d['interface']} "
            f"(link: {d['details']['link']}, protocol: {d['details']['protocol']})"
        )

    prompt = f"""You are a network operations AI analyzing live data from a Cisco router/switch lab.

CURRENT NETWORK STATE:
{chr(10).join(summary)}

DOWN INTERFACES:
{chr(10).join(down_detail) if down_detail else "  None — all interfaces healthy."}

Your job:
1. Analyze the state above.
2. For each down interface, decide: AUTO-FIX or ESCALATE.
   - AUTO-FIX if: likely a transient link issue or admin shutdown.
   - ESCALATE if: device is unreachable or multiple interfaces are down.
3. Return ONLY valid JSON in this exact format:

{{
  "summary": "One sentence description.",
  "actions": [
    {{
      "device": "device name",
      "host": "IP address",
      "interface": "interface name",
      "decision": "AUTO-FIX",
      "reason": "brief reason"
    }}
  ],
  "overall_status": "HEALTHY"
}}
"""
    return prompt

def run_ai_cycle():
    print("\n" + "=" * 60)
    print("AI AGENT: Starting observation cycle (Powered by Gemini)")

    poll_results = poll_all_devices()
    down_interfaces = get_down_interfaces(poll_results)

    print(f"AI AGENT: Sending data to {AI_MODEL} (via Ollama) for analysis...")
    prompt = build_prompt(poll_results, down_interfaces)

    raw = ""
    try:
        # Call Ollama API
        payload = {
            "model": AI_MODEL,
            "prompt": prompt,
            "stream": False,
            "format": "json"  # Instruct Ollama to return valid JSON
        }
        response = requests.post(f"{OLLAMA_URL}/api/generate", json=payload)
        response.raise_for_status()
        raw = response.json().get("response", "").strip()

        # Gemini often wraps JSON in markdown blocks
        if "```json" in raw:
            raw = raw.split("```json")[1].split("```")[0]
        elif "```" in raw:
            raw = raw.split("```")[1].split("```")[0]
            
        parsed = json.loads(raw.strip())
        decision = {
            "summary": parsed.get("summary", "No summary provided."),
            "actions": parsed.get("actions", []),
            "overall_status": parsed.get("overall_status", "UNKNOWN")
        }
    except requests.exceptions.ConnectionError:
        print(f"❌ ERROR: Cannot connect to Ollama at {OLLAMA_URL}. Is Ollama running?")
        return
    except Exception as e:
        print(f"❌ Gemini returned invalid format: {e}")
        print(f"Raw output: {raw}")
        return

    print(f"\nAI ANALYSIS: {decision['summary']}")
    print(f"OVERALL STATUS: {decision['overall_status']}")

    if not decision.get("actions"):
        print("✅ No actions needed.")
        return

    for action in decision["actions"]:
        if action["decision"] == "AUTO-FIX":
            success = fix_interface(action["host"], action["interface"])
            print(f"  ✅ Applied fix to {action['interface']}" if success else "  ❌ Fix failed")
        else:
            print(f"  🚨 ESCALATING: {action['reason']}")

def run_loop():
    print(f"=== Real AIOps Agent Started (Model: {AI_MODEL}) ===")
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