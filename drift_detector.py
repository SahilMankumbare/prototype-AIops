import json
import requests
from config import OLLAMA_URL, AI_MODEL

def classify_drift_with_ai(diff_text: str, device_name: str) -> dict:
    """Send the diff to Ollama to classify changes."""

    if not diff_text.strip():
        return {"classification": "NO_DRIFT", "summary": "No changes.", "risky": False, "rollback_commands": []}

    prompt = f"""Analyze this Cisco config diff and return ONLY JSON:
Device: {device_name}
DIFF:
{diff_text}

Return format:
{{
  "classification": "BENIGN" | "RISKY" | "CRITICAL",
  "summary": "explanation",
  "risky": true/false,
  "risk_reason": "why",
  "rollback_commands": ["cmds"]
}}
"""

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

        # Strip markdown code fences if present
        if "```json" in raw:
            raw = raw.split("```json")[1].split("```")[0]
        elif "```" in raw:
            raw = raw.split("```")[1].split("```")[0]

        parsed = json.loads(raw.strip())

        # Ensure required keys exist with fallbacks
        return {
            "classification": parsed.get("classification", "ERROR"),
            "summary":        parsed.get("summary", "No summary."),
            "risky":          parsed.get("risky", False),
            "risk_reason":    parsed.get("risk_reason", ""),
            "rollback_commands": parsed.get("rollback_commands", [])
        }
    except requests.exceptions.Timeout:
        return {"classification": "ERROR", "summary": "Ollama timed out.", "risky": True, "rollback_commands": []}
    except json.JSONDecodeError as e:
        return {"classification": "ERROR", "summary": f"Bad JSON from model: {e} | Raw: {raw[:200]}", "risky": True, "rollback_commands": []}
    except Exception as e:
        return {"classification": "ERROR", "summary": f"AI error: {str(e)}", "risky": True, "rollback_commands": []}