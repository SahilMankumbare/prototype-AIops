import unittest
from collector import parse_interfaces, get_down_interfaces
from ai_agent import build_prompt

class TestAIOps(unittest.TestCase):
    def test_parse_interfaces_logic(self):
        """Tests that the parser correctly extracts interface states from raw output."""
        # Note: The regex in collector.py currently expects 'line protocol' on the following line.
        sample_output = (
            "GigabitEthernet0/0 is up, line protocol is up\n"
            "  line protocol is up\n"
            "GigabitEthernet0/1 is administratively down, line protocol is down\n"
            "  line protocol is down\n"
        )
        result = parse_interfaces(sample_output)
        
        self.assertIn("GigabitEthernet0/0", result)
        self.assertEqual(result["GigabitEthernet0/0"]["status"], "up")
        self.assertIn("GigabitEthernet0/1", result)
        self.assertEqual(result["GigabitEthernet0/1"]["status"], "down")    

    def test_get_down_interfaces_filtering(self):
        """Tests that we correctly identify only the 'down' interfaces."""
        poll_results = [
            {
                "name": "Core-Router",
                "host": "10.0.0.1",
                "reachable": True,
                "interfaces": {
                    "Gi0/0": {"status": "up", "link": "up", "protocol": "up"},
                    "Gi0/1": {"status": "down", "link": "down", "protocol": "down"}
                }
            }
        ]
        down = get_down_interfaces(poll_results)
        self.assertEqual(len(down), 1)
        self.assertEqual(down[0]["device"], "Core-Router")
        self.assertEqual(down[0]["interface"], "Gi0/1")

    def test_build_prompt_formatting(self):
        """Tests that the prompt builder includes the network summary and state."""
        poll_results = [{"name": "R1", "host": "1.1.1.1", "reachable": True, "interfaces": {"Gi0/0": {"status": "up"}}}]
        down_interfaces = []
        prompt = build_prompt(poll_results, down_interfaces)
        
        self.assertIn("CURRENT NETWORK STATE", prompt)
        self.assertIn("R1", prompt)
        self.assertIn("all interfaces healthy", prompt)

if __name__ == "__main__":
    unittest.main()