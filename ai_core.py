"""
ai_core.py
----------
AI Intelligence Layer for Real AIOps.
Provides conversation memory, proactive network analysis,
root cause analysis, predictive alerts, and autonomous diagnosis.
"""

import json
import time
import threading
from datetime import datetime
from typing import Optional
from collections import deque
import requests
from config import OLLAMA_URL, AI_MODEL


def extract_json(text: str) -> Optional[dict]:
    """Robustly extract JSON from model output that may contain extra text."""
    if not text:
        return None
    text = text.strip()
    # Remove markdown code fences first
    if "```json" in text:
        text = text.split("```json")[1].split("```")[0].strip()
    elif "```" in text:
        text = text.split("```")[1].split("```")[0].strip()
    # Try direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Find first { and last } and try that substring
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(text[start:end+1])
        except json.JSONDecodeError:
            pass
    return None


class ConversationMemory:
    """Maintains chat history with context windowing for coherent multi-turn conversation."""

    def __init__(self, max_turns: int = 10, max_tokens: int = 2048):
        self.history: list[dict] = []
        self.max_turns = max_turns
        self.max_tokens = max_tokens
        self.lock = threading.Lock()

    def add(self, role: str, content: str):
        with self.lock:
            self.history.append({"role": role, "content": content})
            if len(self.history) > self.max_turns * 2:
                self.history = self.history[-(self.max_turns * 2):]

    def build_context(self, system_prompt: str = "") -> str:
        with self.lock:
            if not self.history:
                return system_prompt
            context = system_prompt + "\n\n--- Conversation History ---\n"
            for entry in self.history[-self.max_turns * 2:]:
                prefix = "User" if entry["role"] == "user" else "Assistant"
                context += f"{prefix}: {entry['content']}\n"
            context += "\n--- End of History ---\n"
            return context

    def get_recent(self, n: int = 3) -> list[dict]:
        with self.lock:
            return self.history[-n * 2:]

    def clear(self):
        with self.lock:
            self.history.clear()


class NetworkTrendTracker:
    """Tracks historical network state over time for trend analysis and predictions."""

    def __init__(self, max_samples: int = 60):
        self.snapshots: deque[dict] = deque(maxlen=max_samples)
        self.lock = threading.Lock()

    def record(self, poll_data: list[dict]):
        timestamp = time.time()
        summary = {
            "timestamp": timestamp,
            "time_str": datetime.fromtimestamp(timestamp).strftime("%H:%M:%S"),
            "devices": []
        }
        for device in poll_data:
            dev_summary = {
                "name": device.get("name"),
                "host": device.get("host"),
                "reachable": device.get("reachable", False),
                "interface_count": len(device.get("interfaces", {})),
                "up": 0,
                "down": 0,
                "interfaces": {}
            }
            for name, info in device.get("interfaces", {}).items():
                status = info.get("status", "unknown")
                if status == "up":
                    dev_summary["up"] += 1
                else:
                    dev_summary["down"] += 1
                dev_summary["interfaces"][name] = status
            summary["devices"].append(dev_summary)
        with self.lock:
            self.snapshots.append(summary)

    def get_interface_history(self, device_name: str, interface: str, n: int = 10) -> list[dict]:
        with self.lock:
            recent = list(self.snapshots)[-n:]
        result = []
        for snap in recent:
            for dev in snap["devices"]:
                if dev["name"] == device_name:
                    status = dev["interfaces"].get(interface)
                    if status:
                        result.append({"time": snap["time_str"], "status": status})
        return result

    def get_flapping_interfaces(self, window: int = 10) -> list[dict]:
        with self.lock:
            recent = list(self.snapshots)[-window:]
        if len(recent) < 3:
            return []
        flapping = []
        for dev in recent[-1]["devices"]:
            dev_name = dev["name"]
            for intf_name in dev["interfaces"]:
                states = []
                for snap in recent:
                    for d in snap["devices"]:
                        if d["name"] == dev_name:
                            states.append(d["interfaces"].get(intf_name))
                changes = sum(1 for i in range(1, len(states)) if states[i] != states[i - 1])
                if changes >= 3 and states[-1] == "down":
                    flapping.append({
                        "device": dev_name,
                        "interface": intf_name,
                        "changes": changes,
                        "current": states[-1]
                    })
        return flapping

    def get_trend_summary(self) -> str:
        with self.lock:
            if len(self.snapshots) < 2:
                return "Not enough data for trend analysis yet."
            first = self.snapshots[0]
            last = self.snapshots[-1]
        lines = []
        for dev_last in last["devices"]:
            name = dev_last["name"]
            dev_first = next((d for d in first["devices"] if d["name"] == name), None)
            if not dev_first:
                continue
            delta_down = dev_last["down"] - dev_first["down"]
            direction = "improving" if delta_down < 0 else ("worsening" if delta_down > 0 else "stable")
            lines.append(f"{name}: {dev_last['up']} up / {dev_last['down']} down ({direction})")
        return "\n".join(lines)


class AIAnalyzer:
    """Core AI analysis engine with prompt templates for different intelligence tasks."""

    @staticmethod
    def call_ollama(prompt: str, system_hint: str = "", timeout: int = 60) -> Optional[str]:
        payload = {
            "model": AI_MODEL,
            "prompt": prompt,
            "stream": False,
        }
        if system_hint:
            payload["system"] = system_hint
        try:
            resp = requests.post(f"{OLLAMA_URL}/api/generate", json=payload, timeout=timeout)
            resp.raise_for_status()
            return resp.json().get("response", "").strip()
        except Exception as e:
            return None

    @staticmethod
    def call_ollama_json(prompt: str, timeout: int = 60) -> Optional[dict]:
        prompt_with_hint = prompt + "\n\nReturn ONLY valid JSON. No markdown, no explanation."
        try:
            payload = {
                "model": AI_MODEL,
                "prompt": prompt_with_hint,
                "stream": False,
                "format": "json"
            }
            resp = requests.post(f"{OLLAMA_URL}/api/generate", json=payload, timeout=timeout)
            resp.raise_for_status()
            raw = resp.json().get("response", "").strip()
            return extract_json(raw)
        except Exception:
            return None

    @staticmethod
    def analyze_network_health(poll_data: list[dict], trend_summary: str) -> dict:
        prompt = f"""You are a senior network AI analyzing a live enterprise network.
Current time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

DEVICE STATES:
"""
        for device in poll_data:
            if device.get("reachable"):
                up = sum(1 for i in device["interfaces"].values() if i["status"] == "up")
                down = sum(1 for i in device["interfaces"].values() if i["status"] == "down")
                prompt += f"- {device['name']} ({device['host']}): {up} up, {down} down\n"
                for name, info in device["interfaces"].items():
                    if info["status"] == "down":
                        prompt += f"    {name}: link={info.get('link')}, proto={info.get('protocol')}\n"
            else:
                prompt += f"- {device['name']} ({device['host']}): UNREACHABLE - {device.get('error')}\n"

        prompt += f"""
TREND ANALYSIS (since tracking began):
{trend_summary}

Analyze the network state deeply. Consider:
1. Is there a pattern to the failures (same device, same interface type)?
2. Could unreachable devices indicate a upstream switch or routing failure?
3. Are flapping interfaces present?
4. What is the severity and business impact?

Return JSON:
{{
  "health_score": 0-100,
  "status": "HEALTHY" | "WARNING" | "CRITICAL",
  "summary": "one-line summary",
  "issues": ["issue1", "issue2"],
  "recommendations": ["recommendation1"],
  "insight": "deeper technical insight about root cause patterns"
}}"""
        return AIAnalyzer.call_ollama_json(prompt) or {
            "health_score": 50, "status": "WARNING",
            "summary": "AI analysis unavailable - using fallback.",
            "issues": [], "recommendations": [], "insight": ""
        }

    @staticmethod
    def root_cause_analysis(device_name: str, interface: str, poll_data: list[dict],
                            interface_history: list[dict], trend_summary: str) -> str:
        history_str = "\n".join([f"  {h['time']}: {h['status']}" for h in interface_history])
        prompt = f"""You are a network root cause analysis AI.

An interface is DOWN:
- Device: {device_name}
- Interface: {interface}

Recent interface history (last {len(interface_history)} polls):
{history_str}

Current network state:
"""
        for device in poll_data:
            up = sum(1 for i in device.get("interfaces", {}).values() if i["status"] == "up")
            down = sum(1 for i in device.get("interfaces", {}).values() if i["status"] == "down")
            prompt += f"- {device.get('name')} ({device.get('host')}): {up} up, {down} down" + (" UNREACHABLE" if not device.get("reachable") else "") + "\n"

        prompt += f"""
Trends: {trend_summary}

Analyze possible root causes:
1. Is this an isolated interface issue (cable, port) or part of a larger pattern?
2. Are multiple interfaces on the same device down? (line card / module failure)
3. Are multiple devices affected? (upstream switch / power issue)
4. Is the device itself unreachable? (device offline)
5. Is the interface flapping? (physical layer issue)

Give a concise root cause assessment and recommended next steps."""
        return AIAnalyzer.call_ollama(prompt) or "Root cause analysis unavailable."

    @staticmethod
    def predictive_alert(device_name: str, interface: str, status: str,
                         error_counters: Optional[dict] = None) -> Optional[str]:
        prompt = f"""You are a predictive network AI. Given this interface data, assess risk of future failure:

Device: {device_name}
Interface: {interface}
Current status: {status}
"""
        if error_counters:
            prompt += f"Error counters: {json.dumps(error_counters)}\n"

        prompt += """
Predict: Is this interface likely to fail in the next 24 hours?
Consider: current status, that this is a Cisco router in a lab environment.

Return a single short assessment (1-2 sentences). If healthy, say so."""
        return AIAnalyzer.call_ollama(prompt)

    @staticmethod
    def autonomous_diagnosis(device_name: str, symptoms: list[str],
                             poll_data: list[dict]) -> str:
        prompt = f"""You are an autonomous network troubleshooter.

Device: {device_name}
Reported symptoms: {', '.join(symptoms)}

Current network context:
"""
        for d in poll_data:
            prompt += f"- {d.get('name')}: reachable={d.get('reachable')}, "
            if d.get("interfaces"):
                prompt += f"interfaces: {json.dumps(d['interfaces'])}"
            prompt += "\n"

        prompt += """
Perform a structured diagnosis:
1. What additional information do you need?
2. What commands would you run? (e.g., show ip route, show cdp neighbors, ping)
3. What is your differential diagnosis?
4. What is the most likely root cause?

Provide a concise diagnosis."""
        return AIAnalyzer.call_ollama(prompt) or "Autonomous diagnosis unavailable."


class AIInsights:
    """Aggregated AI insights generated by background analysis."""

    def __init__(self):
        self.insights: list[dict] = []
        self.lock = threading.Lock()
        self.last_analysis: Optional[str] = None
        self.health_score: int = 100
        self.overall_status: str = "HEALTHY"

    def update(self, analysis: dict):
        with self.lock:
            self.last_analysis = datetime.now().isoformat()
            self.health_score = analysis.get("health_score", 100)
            self.overall_status = analysis.get("status", "HEALTHY")
            new_insight = {
                "timestamp": self.last_analysis,
                "status": self.overall_status,
                "score": self.health_score,
                "summary": analysis.get("summary", ""),
                "issues": analysis.get("issues", []),
                "recommendations": analysis.get("recommendations", []),
                "insight": analysis.get("insight", "")
            }
            self.insights.append(new_insight)
            if len(self.insights) > 20:
                self.insights = self.insights[-20:]

    def get_latest(self) -> dict:
        with self.lock:
            if self.insights:
                return self.insights[-1]
            return {"status": "UNKNOWN", "score": 100, "summary": "Waiting for first analysis...", "issues": [], "recommendations": []}


chat_memory = ConversationMemory()
trend_tracker = NetworkTrendTracker()
ai_insights = AIInsights()
