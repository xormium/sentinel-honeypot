# 🍯 HoneyTrap Pro — Cybersecurity Honeypot

A Python-based multi-service honeypot with a real-time web dashboard for
threat intelligence, credential harvesting analysis, and attack visualization.

---

## Features

| Feature | Details |
|---|---|
| **Fake SSH** | Full Paramiko-based SSH handshake on port 2222 |
| **Fake FTP** | RFC-compliant FTP server on port 2121 |
| **Fake HTTP** | Router admin panel lure on port 8888 |
| **Fake Telnet** | Unix login prompt on port 2323 |
| **Fake SMTP** | Mail server on port 2525 |
| **Web Dashboard** | Live attack feed, charts, credential harvest at port 5000 |
| **SQLite Logging** | All events stored in `honeypot.db` |
| **File Logging** | Plain-text log in `honeypot.log` |

---

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Run the honeypot

```bash
python honeypot.py
```

### 3. Open dashboard

Navigate to **http://localhost:5000** in your browser.

---

## Ports Used

| Service | Port | Protocol |
|---------|------|----------|
| SSH     | 2222 | TCP |
| FTP     | 2121 | TCP |
| HTTP    | 8888 | TCP |
| Telnet  | 2323 | TCP |
| SMTP    | 2525 | TCP |
| Dashboard | 5000 | HTTP |

> Using non-standard ports avoids the need for root/admin privileges.
> To use standard ports (22, 21, 80…) you need to run as root or use
> `iptables` port-forwarding rules.

---

## Port Forwarding (Optional — standard ports)

On Linux, forward privileged ports without running as root:

```bash
# Forward port 22 → 2222
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222

# Forward port 21 → 2121
sudo iptables -t nat -A PREROUTING -p tcp --dport 21 -j REDIRECT --to-port 2121
```

---

## Dashboard Panels

- **Live Attack Feed** — Real-time stream of all connection attempts
- **Service Breakdown** — Doughnut chart of attacks per service
- **Attack Timeline** — 24-hour bar chart
- **Top Attacker IPs** — Ranked bar chart of most active IPs
- **Harvested Credentials** — All username/password pairs captured
- **Honeypot Services** — Status of all active sensors

---

## Skills Learned

1. **Threat intelligence** — Identify attacker IPs, tools, and techniques
2. **Malware capture** — Catch payloads sent by automated scanners
3. **Credential analysis** — Understand what password lists attackers use
4. **Network protocol simulation** — SSH, FTP, Telnet, HTTP, SMTP
5. **Cybersecurity monitoring** — Real-time dashboard design and logging

---

## ⚠ Legal & Ethical Notice

> Deploy **only** on networks and systems you own or have explicit written
> authorization to monitor. Unauthorized honeypot deployment may violate
> computer fraud laws in your jurisdiction. This tool is intended strictly
> for educational use, authorized penetration testing, and defensive
> security research.
