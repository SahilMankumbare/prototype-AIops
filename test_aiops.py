"""
Comprehensive test suite for Real AIOps system.
Tests collector, AI core, drift detection, router API parsing, and remediation.
"""

import unittest
import json
import os
import tempfile
from unittest.mock import patch, MagicMock
from datetime import datetime

from collector import parse_interfaces, parse_acls, get_down_interfaces
from ai_agent import build_prompt
from ai_core import ConversationMemory, NetworkTrendTracker, AIAnalyzer
from drift_detector import generate_diff, classify_drift_with_ai, golden_path, load_golden_config
from router_api import (
    parse_command_regex,
    normalize_interface_name,
    normalize_acl_action,
    normalize_acl_address,
    cidr_to_wildcard,
    action_requires_approval,
    planned_commands_for_action,
    validate_parsed_action,
    extract_interface_name,
)


# ────────────────────────────────────────────────────────────
# COLLECTOR TESTS
# ────────────────────────────────────────────────────────────

class TestParseInterfaces(unittest.TestCase):
    """Tests for collector.parse_interfaces()"""

    def test_parse_up_interfaces(self):
        sample = "GigabitEthernet0/0 is up, line protocol is up\n"
        result = parse_interfaces(sample)
        self.assertIn("GigabitEthernet0/0", result)
        self.assertEqual(result["GigabitEthernet0/0"]["status"], "up")

    def test_parse_down_interfaces(self):
        sample = "GigabitEthernet0/1 is down, line protocol is down\n"
        result = parse_interfaces(sample)
        self.assertIn("GigabitEthernet0/1", result)
        self.assertEqual(result["GigabitEthernet0/1"]["status"], "down")

    def test_parse_admin_down_interfaces(self):
        sample = "GigabitEthernet0/1 is administratively down, line protocol is down\n"
        result = parse_interfaces(sample)
        self.assertIn("GigabitEthernet0/1", result)
        self.assertEqual(result["GigabitEthernet0/1"]["status"], "down")

    def test_parse_multiple_interfaces(self):
        sample = (
            "GigabitEthernet0/0 is up, line protocol is up\n"
            "GigabitEthernet0/1 is down, line protocol is down\n"
            "FastEthernet1/0 is up, line protocol is up\n"
        )
        result = parse_interfaces(sample)
        self.assertEqual(len(result), 3)
        self.assertEqual(result["GigabitEthernet0/0"]["status"], "up")
        self.assertEqual(result["GigabitEthernet0/1"]["status"], "down")
        self.assertEqual(result["FastEthernet1/0"]["status"], "up")

    def test_parse_link_and_protocol_mismatch(self):
        sample = "GigabitEthernet0/0 is up, line protocol is down\n"
        result = parse_interfaces(sample)
        self.assertEqual(result["GigabitEthernet0/0"]["status"], "down")

    def test_parse_empty_input(self):
        result = parse_interfaces("")
        self.assertEqual(result, {})

    def test_parse_no_interfaces(self):
        result = parse_interfaces("Some router banner text\nwith no interface data\n")
        self.assertEqual(result, {})


class TestParseAcls(unittest.TestCase):
    """Tests for collector.parse_acls()"""

    def test_parse_standard_acl(self):
        sample = "Standard IP access list 1\n  10 permit 192.168.1.0, wildcard bits 0.0.0.255\n"
        result = parse_acls(sample)
        self.assertIn("1", result)
        self.assertEqual(result["1"]["type"], "standard")
        self.assertEqual(len(result["1"]["rules"]), 1)
        self.assertEqual(result["1"]["rules"][0]["action"], "permit")

    def test_parse_extended_acl(self):
        sample = "Extended IP access list 100\n  10 deny ip 192.168.1.0 0.0.0.255 192.168.2.0 0.0.0.255\n"
        result = parse_acls(sample)
        self.assertIn("100", result)
        self.assertEqual(result["100"]["type"], "extended")
        self.assertEqual(result["100"]["rules"][0]["action"], "deny")

    def test_parse_multiple_acls(self):
        sample = (
            "Standard IP access list 1\n  10 permit any\n"
            "Extended IP access list 100\n  10 deny ip any any\n"
        )
        result = parse_acls(sample)
        self.assertEqual(len(result), 2)
        self.assertIn("1", result)
        self.assertIn("100", result)

    def test_parse_empty(self):
        result = parse_acls("")
        self.assertEqual(result, {})

    def test_parse_no_acls(self):
        result = parse_acls("show access-lists\nNo ACLs configured\n")
        self.assertEqual(result, {})


class TestGetDownInterfaces(unittest.TestCase):
    """Tests for collector.get_down_interfaces()"""

    def setUp(self):
        self.poll_results = [
            {
                "name": "R1",
                "host": "192.168.1.1",
                "reachable": True,
                "interfaces": {
                    "Gi0/0": {"status": "up", "link": "up", "protocol": "up"},
                    "Gi0/1": {"status": "down", "link": "down", "protocol": "down"},
                }
            }
        ]

    def test_finds_down_interfaces(self):
        down = get_down_interfaces(self.poll_results)
        self.assertEqual(len(down), 1)
        self.assertEqual(down[0]["device"], "R1")
        self.assertEqual(down[0]["interface"], "Gi0/1")

    def test_skips_unreachable_devices(self):
        self.poll_results[0]["reachable"] = False
        down = get_down_interfaces(self.poll_results)
        self.assertEqual(len(down), 0)

    def test_empty_when_all_up(self):
        self.poll_results[0]["interfaces"]["Gi0/1"]["status"] = "up"
        down = get_down_interfaces(self.poll_results)
        self.assertEqual(len(down), 0)

    def test_multiple_down_interfaces(self):
        self.poll_results[0]["interfaces"]["Gi0/2"] = {"status": "down", "link": "down", "protocol": "down"}
        down = get_down_interfaces(self.poll_results)
        self.assertEqual(len(down), 2)


# ────────────────────────────────────────────────────────────
# AI AGENT TESTS
# ────────────────────────────────────────────────────────────

class TestBuildPrompt(unittest.TestCase):
    """Tests for ai_agent.build_prompt()"""

    def test_prompt_contains_network_state(self):
        poll = [{"name": "R1", "host": "1.1.1.1", "reachable": True,
                  "interfaces": {"Gi0/0": {"status": "up"}}}]
        prompt = build_prompt(poll, [])
        self.assertIn("CURRENT NETWORK STATE", prompt)
        self.assertIn("R1", prompt)
        self.assertIn("all interfaces healthy", prompt)

    def test_prompt_includes_down_interfaces(self):
        poll = [{"name": "R1", "host": "1.1.1.1", "reachable": True,
                  "interfaces": {"Gi0/0": {"status": "down", "link": "down", "protocol": "down"}}}]
        down = [{"device": "R1", "host": "1.1.1.1", "interface": "Gi0/0",
                  "details": {"status": "down", "link": "down", "protocol": "down"}}]
        prompt = build_prompt(poll, down)
        self.assertIn("DOWN INTERFACES", prompt)
        self.assertIn("Gi0/0", prompt)

    def test_prompt_requests_json(self):
        poll = [{"name": "R1", "host": "1.1.1.1", "reachable": True,
                  "interfaces": {"Gi0/0": {"status": "up"}}}]
        prompt = build_prompt(poll, [])
        self.assertIn("JSON", prompt)

    def test_prompt_includes_unreachable(self):
        poll = [{"name": "R1", "host": "1.1.1.1", "reachable": False, "error": "Timeout"}]
        prompt = build_prompt(poll, [])
        self.assertIn("UNREACHABLE", prompt)
        self.assertIn("Timeout", prompt)

    def test_prompt_down_count(self):
        poll = [{"name": "R1", "host": "1.1.1.1", "reachable": True,
                  "interfaces": {"Gi0/0": {"status": "up"}, "Gi0/1": {"status": "down"}}}]
        prompt = build_prompt(poll, [])
        self.assertIn("1 interfaces DOWN", prompt)


# ────────────────────────────────────────────────────────────
# AI CORE TESTS
# ────────────────────────────────────────────────────────────

class TestConversationMemory(unittest.TestCase):
    """Tests for ai_core.ConversationMemory"""

    def setUp(self):
        self.memory = ConversationMemory(max_turns=3)

    def test_add_and_build_context(self):
        self.memory.add("user", "hello")
        self.memory.add("assistant", "hi there")
        ctx = self.memory.build_context()
        self.assertIn("hello", ctx)
        self.assertIn("hi there", ctx)

    def test_empty_history(self):
        ctx = self.memory.build_context("system prompt")
        self.assertEqual(ctx.strip(), "system prompt")

    def test_context_windowing(self):
        for i in range(10):
            self.memory.add("user", f"msg{i}")
            self.memory.add("assistant", f"reply{i}")
        ctx = self.memory.build_context()
        # Should contain only the last 3 turns (6 entries)
        self.assertIn("msg9", ctx)
        self.assertNotIn("msg0", ctx)

    def test_clear(self):
        self.memory.add("user", "hello")
        self.memory.clear()
        ctx = self.memory.build_context("prompt")
        self.assertEqual(ctx.strip(), "prompt")

    def test_get_recent(self):
        self.memory.add("user", "a")
        self.memory.add("assistant", "b")
        self.memory.add("user", "c")
        recent = self.memory.get_recent(n=1)
        self.assertEqual(len(recent), 2)
        self.assertEqual(recent[1]["role"], "user")
        self.assertEqual(recent[1]["content"], "c")


class TestNetworkTrendTracker(unittest.TestCase):
    """Tests for ai_core.NetworkTrendTracker"""

    def setUp(self):
        self.tracker = NetworkTrendTracker(max_samples=10)

    def test_record_and_trend_summary(self):
        poll = [{"name": "R1", "host": "1.1.1.1", "reachable": True,
                  "interfaces": {"Gi0/0": {"status": "up"}, "Gi0/1": {"status": "down"}}}]
        self.tracker.record(poll)
        self.tracker.record(poll)
        summary = self.tracker.get_trend_summary()
        self.assertIn("R1", summary)

    def test_no_data_trend_summary(self):
        summary = self.tracker.get_trend_summary()
        self.assertIn("Not enough data", summary)

    def test_flapping_detection(self):
        for status in ["up", "down", "up", "down"]:
            poll = [{"name": "R1", "host": "1.1.1.1", "reachable": True,
                      "interfaces": {"Gi0/0": {"status": status}}}]
            self.tracker.record(poll)
        flapping = self.tracker.get_flapping_interfaces(window=10)
        self.assertTrue(len(flapping) > 0)

    def test_no_flapping(self):
        for _ in range(5):
            poll = [{"name": "R1", "host": "1.1.1.1", "reachable": True,
                      "interfaces": {"Gi0/0": {"status": "up"}}}]
            self.tracker.record(poll)
        flapping = self.tracker.get_flapping_interfaces()
        self.assertEqual(len(flapping), 0)

    def test_interface_history(self):
        poll = [{"name": "R1", "host": "1.1.1.1", "reachable": True,
                  "interfaces": {"Gi0/0": {"status": "up"}}}]
        self.tracker.record(poll)
        history = self.tracker.get_interface_history("R1", "Gi0/0")
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["status"], "up")


# ────────────────────────────────────────────────────────────
# DRIFT DETECTOR TESTS
# ────────────────────────────────────────────────────────────

class TestDriftDetector(unittest.TestCase):
    """Tests for drift_detector"""

    def test_generate_diff_with_changes(self):
        golden = "hostname R1\ninterface Gi0/0\n ip address 10.0.0.1 255.255.255.0\n"
        current = "hostname R1\ninterface Gi0/0\n ip address 10.0.0.2 255.255.255.0\n"
        diff = generate_diff(golden, current)
        self.assertIn("10.0.0.1", diff)
        self.assertIn("10.0.0.2", diff)

    def test_generate_diff_no_changes(self):
        config = "hostname R1\n"
        diff = generate_diff(config, config)
        self.assertEqual(diff.strip(), "")

    def test_generate_diff_added_lines(self):
        golden = "hostname R1\n"
        current = "hostname R1\ninterface Gi0/0\n no shutdown\n"
        diff = generate_diff(golden, current)
        self.assertIn("interface Gi0/0", diff)

    def test_generate_diff_removed_lines(self):
        golden = "hostname R1\ninterface Gi0/0\n no shutdown\n"
        current = "hostname R1\n"
        diff = generate_diff(golden, current)
        self.assertIn("no shutdown", diff)

    def test_golden_path(self):
        path = golden_path("R1")
        self.assertTrue(path.endswith("R1_golden.txt"))
        self.assertIn("golden_configs", path)

    def test_load_golden_config_not_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            original_dir = os.getcwd()
            os.chdir(tmp)
            try:
                result = load_golden_config("NonExistent")
                self.assertIsNone(result)
            finally:
                os.chdir(original_dir)

    def test_classify_drift_no_diff(self):
        from drift_detector import classify_drift_with_ai
        result = classify_drift_with_ai("", "R1")
        self.assertEqual(result["classification"], "NO_DRIFT")

    def test_classify_drift_with_diff(self):
        from drift_detector import classify_drift_with_ai
        diff = "- hostname R1\n+ hostname R1-modified\n"
        result = classify_drift_with_ai(diff, "R1")
        self.assertIn(result["classification"], ["BENIGN", "RISKY", "CRITICAL", "ERROR", "NO_DRIFT"])


# ────────────────────────────────────────────────────────────
# ROUTER API PARSING TESTS
# ────────────────────────────────────────────────────────────

class TestParseCommandRegex(unittest.TestCase):
    """Tests for router_api.parse_command_regex()"""

    def test_show_status(self):
        result = parse_command_regex("what is the network status")
        self.assertEqual(result["action"], "show_status")

    def test_show_acl(self):
        result = parse_command_regex("show me acl")
        self.assertEqual(result["action"], "show_acl")

    def test_show_acl_access_list(self):
        result = parse_command_regex("show access-list")
        self.assertEqual(result["action"], "show_acl")

    def test_show_acls_plural(self):
        result = parse_command_regex("show me the ACLs")
        self.assertEqual(result["action"], "show_acl")

    def test_show_interfaces(self):
        result = parse_command_regex("show interfaces")
        self.assertEqual(result["action"], "show_interfaces")

    def test_show_ip_int_brief(self):
        result = parse_command_regex("show ip int brief")
        self.assertEqual(result["action"], "show_interfaces")

    def test_interface_down(self):
        result = parse_command_regex("shutdown interface Fa0/0")
        self.assertEqual(result["action"], "interface_down")
        self.assertEqual(result["interface"], "Fa0/0")

    def test_interface_up(self):
        result = parse_command_regex("no shutdown on Fa0/1")
        self.assertEqual(result["action"], "interface_up")

    def test_show_config(self):
        result = parse_command_regex("show running config")
        self.assertEqual(result["action"], "show_config")

    def test_show_logs(self):
        result = parse_command_regex("get me logs")
        self.assertEqual(result["action"], "show_logs")

    def test_greeting(self):
        result = parse_command_regex("hello")
        self.assertEqual(result["action"], "chat")

    def test_unknown(self):
        result = parse_command_regex("xyzzy unknown command")
        self.assertEqual(result["action"], "unknown")

    def test_push_acl(self):
        result = parse_command_regex("push acl from 192.168.1.0 to 192.168.2.0 deny")
        self.assertEqual(result["action"], "push_acl")
        self.assertEqual(result["acl_action"], "deny")

    def test_push_acl_allow(self):
        result = parse_command_regex("push acl from 10.0.0.0 to 20.0.0.0 allow")
        self.assertEqual(result["action"], "push_acl")
        self.assertEqual(result["acl_action"], "permit")


class TestNormalizeFunctions(unittest.TestCase):
    """Tests for router_api normalization functions"""

    def test_normalize_interface_fa(self):
        result = normalize_interface_name("Fa0/0")
        self.assertEqual(result, "Fa0/0")

    def test_normalize_interface_gigabit(self):
        result = normalize_interface_name("GigabitEthernet0/1")
        self.assertEqual(result, "GigabitEthernet0/1")

    def test_normalize_interface_shorthand(self):
        result = normalize_interface_name("gi0/2")
        self.assertEqual(result, "Gi0/2")

    def test_normalize_interface_serial(self):
        result = normalize_interface_name("Serial1/0")
        self.assertEqual(result, "Serial1/0")

    def test_normalize_interface_empty(self):
        result = normalize_interface_name("")
        self.assertEqual(result, "")

    def test_normalize_acl_action_allow(self):
        self.assertEqual(normalize_acl_action("allow"), "permit")

    def test_normalize_acl_action_deny(self):
        self.assertEqual(normalize_acl_action("deny"), "deny")

    def test_normalize_acl_action_block(self):
        self.assertEqual(normalize_acl_action("block"), "deny")

    def test_normalize_acl_action_drop(self):
        self.assertEqual(normalize_acl_action("drop"), "deny")

    def test_normalize_acl_address_cidr(self):
        result = normalize_acl_address("192.168.1.0/24")
        self.assertIn("192.168.1.0", result)
        self.assertIn("0.0.0.255", result)

    def test_normalize_acl_address_any(self):
        result = normalize_acl_address("any")
        self.assertEqual(result, "any")

    def test_cidr_to_wildcard_24(self):
        result = cidr_to_wildcard("10.0.0.0/24")
        self.assertIn("0.0.0.255", result)

    def test_cidr_to_wildcard_16(self):
        result = cidr_to_wildcard("10.0.0.0/16")
        self.assertIn("0.0.255", result)

    def test_cidr_to_wildcard_no_prefix(self):
        result = cidr_to_wildcard("10.0.0.1")
        self.assertIn("0.0.0.0", result)

    def test_extract_interface_name(self):
        result = extract_interface_name("shutdown Fa0/0")
        self.assertEqual(result, "Fa0/0")

    def test_extract_interface_name_none(self):
        result = extract_interface_name("show me the logs")
        self.assertEqual(result, "")


class TestActionApproval(unittest.TestCase):
    """Tests for action approval and command planning"""

    def test_interface_up_requires_approval(self):
        self.assertTrue(action_requires_approval({"action": "interface_up", "interface": "Fa0/0"}))

    def test_interface_down_requires_approval(self):
        self.assertTrue(action_requires_approval({"action": "interface_down"}))

    def test_push_acl_requires_approval(self):
        self.assertTrue(action_requires_approval({"action": "push_acl"}))

    def test_show_acl_no_approval(self):
        self.assertFalse(action_requires_approval({"action": "show_acl"}))

    def test_show_interfaces_no_approval(self):
        self.assertFalse(action_requires_approval({"action": "show_interfaces"}))

    def test_chat_no_approval(self):
        self.assertFalse(action_requires_approval({"action": "chat"}))

    def test_planned_commands_interface_up(self):
        cmds = planned_commands_for_action({"action": "interface_up", "interface": "Fa0/0"})
        self.assertIn("no shutdown", cmds)
        self.assertIn("interface Fa0/0", cmds)

    def test_planned_commands_interface_down(self):
        cmds = planned_commands_for_action({"action": "interface_down", "interface": "Fa0/0"})
        self.assertIn("shutdown", cmds)

    def test_planned_commands_show_config(self):
        cmds = planned_commands_for_action({"action": "show_config"})
        self.assertIn("show running-config", cmds)

    def test_planned_commands_push_acl(self):
        cmds = planned_commands_for_action({
            "action": "push_acl", "interface": "Fa0/0",
            "acl_src": "10.0.0.0 0.255.255.255", "acl_dst": "20.0.0.0 0.255.255.255",
            "acl_action": "deny"
        })
        self.assertTrue(any("access-list" in c for c in cmds))
        self.assertTrue(any("ip access-group" in c for c in cmds))


class TestValidateParsedAction(unittest.TestCase):
    """Tests for router_api.validate_parsed_action()"""

    def test_interface_up_adds_interface_from_command(self):
        result = validate_parsed_action("bring Fa0/0 up", {"action": "interface_up"})
        self.assertEqual(result["interface"], "Fa0/0")

    def test_interface_down_no_interface_returns_unknown(self):
        result = validate_parsed_action("shutdown", {"action": "interface_down"})
        self.assertEqual(result["action"], "unknown")

    def test_push_acl_defaults_fastethernet(self):
        result = validate_parsed_action("push acl", {"action": "push_acl"})
        self.assertEqual(result.get("interface"), "FastEthernet0/0")

    def test_non_dict_returns_unknown(self):
        result = validate_parsed_action("test", "not a dict")
        self.assertEqual(result["action"], "unknown")


# ────────────────────────────────────────────────────────────
# RUN
# ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)
