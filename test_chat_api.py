import unittest

from router_api import app, state, state_lock


class TestChatApprovalApi(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        with state_lock:
            state["devices"] = []
            state["pending_approvals"] = {}

    def test_status_chat_is_read_only(self):
        response = self.client.post(
            "/chat",
            json={"message": "what is the network status", "device": "192.168.1.8"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("reply", response.json)
        self.assertNotIn("approval_required", response.json)

    def test_interface_change_requires_approval(self):
        response = self.client.post(
            "/chat",
            json={"message": "shutdown interface Fa0/0", "device": "192.168.1.8"},
        )
        self.assertEqual(response.status_code, 202)
        self.assertTrue(response.json["approval_required"])
        self.assertEqual(response.json["parsed"]["action"], "interface_down")

        pending = self.client.get("/pending-approvals")
        self.assertEqual(len(pending.json["approvals"]), 1)

    def test_natural_interface_phrase_extracts_real_interface(self):
        response = self.client.post(
            "/chat",
            json={"message": "take this fa0/1 interface down", "device": "192.168.1.8"},
        )
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json["parsed"]["action"], "interface_down")
        self.assertEqual(response.json["parsed"]["interface"], "Fa0/1")
        self.assertIn("Fa0/1", response.json["approval"]["description"])
        self.assertEqual(response.json["approval"]["commands"], ["interface Fa0/1", "shutdown"])

    def test_interface_up_phrase_extracts_real_interface(self):
        response = self.client.post(
            "/chat",
            json={"message": "bring this fa0/1 interface up", "device": "192.168.1.8"},
        )
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json["parsed"]["action"], "interface_up")
        self.assertEqual(response.json["parsed"]["interface"], "Fa0/1")

    def test_casual_chat_does_not_execute(self):
        response = self.client.post(
            "/chat",
            json={"message": "how are you", "device": "192.168.1.8"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["parsed"]["action"], "chat")
        self.assertIn("ready", response.json["reply"].lower())

    def test_router_configuration_request_is_config_read(self):
        response = self.client.post(
            "/chat",
            json={"message": "show me routers configuration", "device": "192.168.1.8"},
        )
        self.assertEqual(response.status_code, 202)
        self.assertTrue(response.json["approval_required"])
        self.assertEqual(response.json["parsed"]["action"], "show_config")
        self.assertEqual(response.json["approval"]["commands"], ["show running-config"])

    def test_ai_cannot_invent_interface_for_config_sentence(self):
        from router_api import validate_parsed_action

        parsed = validate_parsed_action(
            "show me routers configuration",
            {"action": "interface_up", "interface": "Ethernet0/0"},
        )
        self.assertEqual(parsed["action"], "unknown")
        self.assertIn("not guess", parsed["answer"])


if __name__ == "__main__":
    unittest.main()
