# Real AIOps — Network Automation with AI

This folder is the **real device** upgrade from the simulation prototype.
It connects to actual Cisco routers/switches in your EVE-NG lab via SSH and SNMP.

## Folder Structure

```
real_aiops/
├── collector.py          # SSH + SNMP poller — pulls real interface data
├── ai_agent.py           # AI brain — calls Ollama API to analyze and decide
├── remediation.py        # Pushes config fixes to real devices via SSH
├── drift_detector.py     # Problem 2 — config drift vs golden baseline
├── golden_config.txt     # Your baseline config snapshot (edit this)
├── config.py             # Device IPs, credentials, SNMP community
├── router_api.py         # Flask dashboard server (shows real data)
├── templates/
│   └── dashboard.html    # Live dashboard UI
└── README.md
```

## Problem Statements Solved

### Problem 1 — Interface Health Monitor & Auto-Remediation
- `collector.py` polls your 3725 router every 30s via SSH (`show interfaces`)
- `ai_agent.py` sends the data to Local Ollama (llama3) → AI decides: fix or escalate
- `remediation.py` SSHes back in and runs `no shutdown` on down interfaces
- Dashboard shows live interface status

### Problem 2 — Config Drift Detection
- `drift_detector.py` snapshots `show running-config` on a schedule
- Diffs it against `golden_config.txt` (your known-good baseline)
- Sends the diff to Local Ollama (llama3) → AI classifies: benign change vs risky
- Risky changes: alert sent + optional rollback

## Setup

### 1. Install dependencies
```bash
pip install flask netmiko requests python-dotenv pysnmp
```

### 2. Configure your devices
Edit `config.py` with your EVE-NG device IPs and credentials.

Devices:
- Router R1: 192.168.1.8, username: admin, password: mypassword
- Switch SW1: 192.168.2.10, username: admin, password: mypassword

#### Device Configuration Commands
Run these commands on Router R1:
```
enable
configure terminal
hostname R1
interface Fa0/0
 ip address dhcp
 no shutdown
interface Fa0/1
 ip address 192.168.2.1 255.255.255.0
 no shutdown
ip ssh version 2
crypto key generate rsa modulus 2048
snmp-server community public RO
end
write memory
```

Run these commands on Switch SW1:
```
enable
configure terminal
hostname SW1
vlan 1
interface vlan 1
 ip address 192.168.2.10 255.255.255.0
 no shutdown
ip default-gateway 192.168.2.1
interface range Eth0/0 - 3
 no shutdown
ip ssh version 2
crypto key generate rsa modulus 2048
snmp-server community public RO
end
write memory
```

### 3. Set your AI provider
The code uses Local Ollama, so it stays free and runs without paid API keys.

For low-RAM laptops, use TinyLlama:
```bash
ollama pull tinyllama
set AI_MODEL=tinyllama
```

If your laptop can handle a larger model, set another Ollama model:
```bash
set AI_MODEL=llama3
```

Ensure Ollama is running on localhost:11434.

### 4. Take your first golden config snapshot
```bash
 --snapshot

This saves the current running config as `golden_config.txt`.

### 5. Run the dashboard
```bash
python router_api.py
```
Open: http://localhost:5001

If port 5001 is already busy, run on another port:
```bash
set DASHBOARD_PORT=5002
python router_api.py
```

The dashboard includes an AI Network Copilot chat panel. Try:
- `what is the network status`
- `get me logs`
- `show running config`
- `shutdown interface Fa0/0`
- `push acl from 192.168.1.0/24 to 192.168.2.0/24 deny on FastEthernet0/0`

Sensitive actions use a human approval layer. Interface changes, ACL pushes, and running-config reads are queued first. Click Approve or Deny in the dashboard before the action is executed.

### 6. Run the AI agent (separate terminal)
```bash
python ai_agent.py
```

### 7. Test drift detection
```bash
python drift_detector.py --check
```

## EVE-NG Tips

- Make sure your EVE-NG management interface is reachable from your host machine (e.g., host on 192.168.1.25)
- Enable SSH on each device: `ip ssh version 2`, `crypto key generate rsa`
- Enable SNMP: `snmp-server community public RO`
- Router R1: Interfaces Fa0/0 (192.168.1.8/24 DHCP), Fa0/1 (192.168.2.1/24 Static)
- Switch SW1: Management Vlan1 (192.168.2.10/24), ip default-gateway 192.168.2.1
- SSH Targets: Router 192.168.1.8, Switch 192.168.2.10
- Default EVE-NG device IPs are in the 192.168.x.x range — check your topology
