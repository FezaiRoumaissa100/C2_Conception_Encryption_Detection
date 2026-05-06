# MYC2_Pannel

A modern, encrypted Command and Control (C2) server with a web dashboard, using **AES-256-GCM** for payload encryption and **TLS (HTTPS)** for transport security.

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
├── server.crt         ← TLS certificate (self-signed, git-ignored)
├── server.key         ← TLS private key (git-ignored)
├── server/            ← C2 server source code
│   ├── server.py      ← Main entry point (HTTPS enabled)
│   ├── crypto.py      ← AES-256-GCM encryption logic
│   ├── routes_c2.py   ← API routes for the agent
│   ├── routes_ui.py   ← API routes for the web interface
│   ├── state.py       ← Shared global variables
│   └── templates/     ← HTML User Interface (MYC2_Pannel)
├── agents/            ← Agent source code
│   └── agent.py       ← Agent executable
├── config/            ← Configuration files
│   └── dnsmasq.conf   ← DNS Spoofing configuration
└── requirements.txt   ← Python dependencies
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

## TLS Certificate Setup

The C2 server runs over **HTTPS** using a self-signed TLS certificate. You must generate the certificate before starting the server.

### Generate the self-signed certificate (on Kali)

```bash
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=micros0ft-update.com"
```

This command:
- Creates a **2048-bit RSA** private key (`server.key`)
- Creates a self-signed **X.509 certificate** (`server.crt`) valid for **365 days**
- Uses `-nodes` to skip passphrase protection on the key
- Sets the Common Name (CN) to `micros0ft-update.com`

> **Note:** The `server.key` and `server.crt` files are listed in `.gitignore` and should **never** be committed to version control.

### Why HTTPS?

| Layer | Protection |
|-------|-----------|
| **TLS (Transport)** | Encrypts the entire HTTP connection — headers, URLs, and body — preventing network-level eavesdropping and man-in-the-middle attacks. |
| **AES-256-GCM (Payload)** | Encrypts the command/response data inside the HTTP body, providing end-to-end confidentiality even if TLS is intercepted or stripped. |

Using both layers together provides **defense in depth**: TLS protects the channel, and AES-256-GCM protects the payload.

---

## DNS Configuration (Victim)

The agent is configured to connect to `https://micros0ft-update.com:5000`. You must point this domain to your Kali IP address (for example `192.168.100.30`).

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

**1. Generate the TLS certificate (first time only, on Kali):**
```bash
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=micros0ft-update.com"
```

**2. Start C2 server (Kali):**
```bash
cd server
python3 server.py
```

**3. Start agent (Ubuntu victim):**
```bash
cd agents
python3 agent.py
```

**Web interface:** https://localhost:5000

> ⚠️ Your browser will show a certificate warning because the certificate is self-signed. This is expected — accept the warning to access the dashboard.

> ℹ️ The agent uses `verify=False` to bypass certificate validation for the self-signed certificate.

---

## Encryption

- Algorithm : AES-256-GCM
- Key size  : 256 bits (32 bytes)
- Nonce     : 12 bytes random per message
- Transport : Base64 over HTTPS (TLS)
