# MYC2_Pannel

A modern, encrypted Command and Control (C2) server with a web dashboard, using AES-256-GCM for secure communication.

## Environment & Scenario

This project is designed to simulate a realistic Command and Control scenario within an internal network environment:
- **Attacker Machine:** Kali Linux (Running the C2 Server & Dashboard)
- **Victim Machine:** Ubuntu (Running the Agent)
- **Network:** Internal network where both machines can communicate via IP addresses (e.g., `192.168.100.x`).
- **Communication:** The victim uses DNS spoofing/forwarding to resolve a fake domain (`micros0ft-update.com`) directly to the Kali attacker's IP address.

## Project Structure

```
.
├── README.md          ← Complete instructions
├── server/            ← C2 server source code
│   ├── server.py      ← Main entry point
│   ├── crypto.py      ← Encryption logic
│   ├── routes_c2.py   ← API routes for the agent
│   ├── routes_ui.py   ← API routes for the web interface
│   ├── state.py       ← Shared global variables
│   ├── templates/     ← HTML User Interface (MYC2_Pannel)
│   └── requirements.txt
├── agent/             ← Agent source code
│   └── agent.py       ← Agent executable
└── config/            ← Configuration files
    └── dnsmasq.conf   ← DNS Spoofing configuration
```

## Installation

```bash

# Install dependencies
pip install flask cryptography requests --break-system-packages

# Install and start dnsmasq (Kali only)
sudo apt install dnsmasq -y
sudo cp config/dnsmasq.conf /etc/dnsmasq.conf
sudo systemctl start dnsmasq
```

---

## DNS Configuration (Victim)

The agent is configured to connect to `http://micros0ft-update.com:5000`. You must point this domain to your Kali IP address (for example `192.168.100.30`).

**On Ubuntu victim — point DNS to Kali:**
```bash
sudo resolvectl dns enp0s9 192.168.100.30
```

*Note: If you do not use `resolvectl` (or for a quick test), you can also modify `/etc/hosts`:*
```bash
echo "192.168.100.30 micros0ft-update.com" | sudo tee -a /etc/hosts
```

**Verify:**
```bash
nslookup micros0ft-update.com
# Expected: Address: 192.168.100.30
```

---

## Usage

**Start C2 server (Kali):**
```bash
cd server
python3 server.py
```

**Start agent (Ubuntu victim):**
```bash
cd agent
python3 agent.py
```

**Web interface:** http://localhost:5000

---

## Encryption

- Algorithm : AES-256-GCM
- Key size  : 256 bits (32 bytes)
- Nonce     : 12 bytes random per message
- Transport : Base64 over HTTP
