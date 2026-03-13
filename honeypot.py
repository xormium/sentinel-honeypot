#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║           HoneyTrap Pro - Cybersecurity Honeypot             ║
║     Defensive threat intelligence & attack monitoring        ║
╚══════════════════════════════════════════════════════════════╝
"""

import socket
import threading
import sqlite3
import json
import time
import os
import sys
import logging
import hashlib
import ipaddress
from datetime import datetime, timedelta
from collections import defaultdict
from flask import Flask, render_template_string, jsonify, request
import paramiko
from paramiko import RSAKey
from io import StringIO

# ─── Configuration ───────────────────────────────────────────────────────────

DB_PATH = "honeypot.db"
LOG_PATH = "honeypot.log"
WEB_PORT = 5000

SERVICES = {
    "SSH":    {"port": 2222,  "enabled": True,  "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"},
    "FTP":    {"port": 2121,  "enabled": True,  "banner": "220 ProFTPD 1.3.5e Server (Debian) ready."},
    "HTTP":   {"port": 8888,  "enabled": True,  "banner": "Apache/2.4.41 (Ubuntu)"},
    "TELNET": {"port": 2323,  "enabled": True,  "banner": "\r\nUbuntu 20.04.6 LTS\r\n\r\nlogin: "},
    "SMTP":   {"port": 2525,  "enabled": True,  "banner": "220 mail.corp.internal ESMTP Postfix"},
    "MYSQL":  {"port": 3307,  "enabled": True,  "banner": None},
}

FAKE_CREDENTIALS = {
    "admin": "admin", "root": "root", "user": "password",
    "test": "test", "guest": "guest", "admin": "123456",
}

# ─── Database Setup ───────────────────────────────────────────────────────────

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS attacks (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            ip          TEXT NOT NULL,
            port        INTEGER NOT NULL,
            service     TEXT NOT NULL,
            username    TEXT,
            password    TEXT,
            payload     TEXT,
            country     TEXT DEFAULT 'Unknown',
            hostname    TEXT,
            user_agent  TEXT,
            success     INTEGER DEFAULT 0,
            session_id  TEXT
        );

        CREATE TABLE IF NOT EXISTS sessions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id  TEXT UNIQUE,
            ip          TEXT,
            service     TEXT,
            start_time  TEXT,
            end_time    TEXT,
            commands    TEXT DEFAULT '[]',
            total_attempts INTEGER DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_attacks_ip ON attacks(ip);
        CREATE INDEX IF NOT EXISTS idx_attacks_service ON attacks(service);
        CREATE INDEX IF NOT EXISTS idx_attacks_timestamp ON attacks(timestamp);
    """)
    conn.commit()
    conn.close()

def log_attack(ip, port, service, username=None, password=None,
               payload=None, success=False, session_id=None, user_agent=None):
    ts = datetime.now().isoformat()
    hostname = ""
    try:
        hostname = socket.getfqdn(ip)
        if hostname == ip:
            hostname = ""
    except:
        pass

    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT INTO attacks
        (timestamp, ip, port, service, username, password, payload, hostname, user_agent, success, session_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (ts, ip, port, service, username, password, payload, hostname, user_agent, int(success), session_id))
    conn.commit()
    conn.close()

    logging.info(f"[{service}] {ip}:{port} | user={username} pass={password} | {'SUCCESS' if success else 'FAIL'}")

# ─── SSH Honeypot ─────────────────────────────────────────────────────────────

class FakeSSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()
        self.username = None
        self.password = None

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        self.username = username
        self.password = password
        sid = hashlib.md5(f"{self.client_ip}{time.time()}".encode()).hexdigest()[:8]
        log_attack(self.client_ip, 2222, "SSH", username, password, session_id=sid)
        # Always deny – pure logging
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password,publickey"

def generate_host_key():
    return RSAKey.generate(2048)

HOST_KEY = generate_host_key()

def handle_ssh_client(client_sock, client_addr):
    ip = client_addr[0]
    try:
        transport = paramiko.Transport(client_sock)
        transport.local_version = SERVICES["SSH"]["banner"]
        transport.add_server_key(HOST_KEY)
        server = FakeSSHServer(ip)
        transport.start_server(server=server)
        chan = transport.accept(20)
        if chan:
            chan.send(b"\r\nAccess denied.\r\n")
            chan.close()
    except Exception:
        pass
    finally:
        try:
            client_sock.close()
        except:
            pass

def ssh_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", SERVICES["SSH"]["port"]))
    sock.listen(100)
    logging.info(f"SSH honeypot listening on port {SERVICES['SSH']['port']}")
    while True:
        try:
            client, addr = sock.accept()
            t = threading.Thread(target=handle_ssh_client, args=(client, addr), daemon=True)
            t.start()
        except Exception as e:
            logging.error(f"SSH accept error: {e}")

# ─── FTP Honeypot ─────────────────────────────────────────────────────────────

def handle_ftp_client(conn, addr):
    ip = addr[0]
    session_id = hashlib.md5(f"{ip}{time.time()}".encode()).hexdigest()[:8]
    username = None
    try:
        conn.send(f"{SERVICES['FTP']['banner']}\r\n".encode())
        conn.settimeout(30)
        while True:
            data = conn.recv(1024).decode(errors="ignore").strip()
            if not data:
                break
            cmd = data.split(" ")[0].upper()
            arg = data[len(cmd):].strip()

            if cmd == "USER":
                username = arg
                log_attack(ip, 2121, "FTP", username=arg, session_id=session_id)
                conn.send(b"331 Password required for " + arg.encode() + b"\r\n")
            elif cmd == "PASS":
                log_attack(ip, 2121, "FTP", username=username, password=arg, session_id=session_id)
                conn.send(b"530 Login incorrect.\r\n")
            elif cmd == "QUIT":
                conn.send(b"221 Goodbye.\r\n")
                break
            elif cmd == "SYST":
                conn.send(b"215 UNIX Type: L8\r\n")
            elif cmd == "FEAT":
                conn.send(b"211-Features:\r\n PASV\r\n211 End\r\n")
            else:
                conn.send(b"530 Please login with USER and PASS.\r\n")
    except Exception:
        pass
    finally:
        conn.close()

def ftp_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", SERVICES["FTP"]["port"]))
    sock.listen(100)
    logging.info(f"FTP honeypot listening on port {SERVICES['FTP']['port']}")
    while True:
        try:
            conn, addr = sock.accept()
            threading.Thread(target=handle_ftp_client, args=(conn, addr), daemon=True).start()
        except Exception as e:
            logging.error(f"FTP error: {e}")

# ─── HTTP Honeypot ────────────────────────────────────────────────────────────

HTTP_LOGIN_PAGE = b"""HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: Apache/2.4.41\r\n\r\n
<!DOCTYPE html><html><head><title>Router Login</title></head><body>
<h2>Netgear Router Admin Panel</h2>
<form method='POST' action='/login'>
  Username: <input name='username'><br>
  Password: <input type='password' name='password'><br>
  <input type='submit' value='Login'>
</form></body></html>"""

def handle_http_client(conn, addr):
    ip = addr[0]
    try:
        conn.settimeout(10)
        data = conn.recv(4096).decode(errors="ignore")
        lines = data.split("\r\n")
        method = lines[0].split(" ")[0] if lines else "GET"
        ua = next((l.split(": ", 1)[1] for l in lines if l.startswith("User-Agent:")), "")
        path = lines[0].split(" ")[1] if len(lines[0].split(" ")) > 1 else "/"

        username = password = None
        if method == "POST" and "\r\n\r\n" in data:
            body = data.split("\r\n\r\n", 1)[1]
            params = dict(p.split("=", 1) for p in body.split("&") if "=" in p)
            username = params.get("username", "")
            password = params.get("password", "")
            log_attack(ip, 8888, "HTTP", username=username, password=password,
                      payload=f"POST {path}", user_agent=ua)
            conn.send(b"HTTP/1.1 401 Unauthorized\r\nContent-Type: text/html\r\n\r\n<h2>Invalid credentials</h2>")
        else:
            log_attack(ip, 8888, "HTTP", payload=f"{method} {path}", user_agent=ua)
            conn.send(HTTP_LOGIN_PAGE)
    except Exception:
        pass
    finally:
        conn.close()

def http_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", SERVICES["HTTP"]["port"]))
    sock.listen(100)
    logging.info(f"HTTP honeypot listening on port {SERVICES['HTTP']['port']}")
    while True:
        try:
            conn, addr = sock.accept()
            threading.Thread(target=handle_http_client, args=(conn, addr), daemon=True).start()
        except Exception as e:
            logging.error(f"HTTP error: {e}")

# ─── Telnet Honeypot ──────────────────────────────────────────────────────────

def handle_telnet_client(conn, addr):
    ip = addr[0]
    session_id = hashlib.md5(f"{ip}{time.time()}".encode()).hexdigest()[:8]
    username = None
    try:
        conn.settimeout(30)
        conn.send(SERVICES["TELNET"]["banner"].encode())
        while True:
            username = b""
            while True:
                ch = conn.recv(1)
                if not ch or ch in (b"\r", b"\n"):
                    break
                username += ch
            username = username.decode(errors="ignore").strip()
            if not username:
                continue
            log_attack(ip, 2323, "TELNET", username=username, session_id=session_id)
            conn.send(b"Password: ")
            password = b""
            while True:
                ch = conn.recv(1)
                if not ch or ch in (b"\r", b"\n"):
                    break
                password += ch
            password = password.decode(errors="ignore").strip()
            log_attack(ip, 2323, "TELNET", username=username, password=password, session_id=session_id)
            conn.send(b"\r\nLogin incorrect\r\n\r\nlogin: ")
    except Exception:
        pass
    finally:
        conn.close()

def telnet_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", SERVICES["TELNET"]["port"]))
    sock.listen(100)
    logging.info(f"Telnet honeypot listening on port {SERVICES['TELNET']['port']}")
    while True:
        try:
            conn, addr = sock.accept()
            threading.Thread(target=handle_telnet_client, args=(conn, addr), daemon=True).start()
        except Exception as e:
            logging.error(f"Telnet error: {e}")

# ─── SMTP Honeypot ────────────────────────────────────────────────────────────

def handle_smtp_client(conn, addr):
    ip = addr[0]
    try:
        conn.settimeout(30)
        conn.send(f"220 {SERVICES['SMTP']['banner']}\r\n".encode())
        while True:
            data = conn.recv(1024).decode(errors="ignore").strip()
            if not data:
                break
            cmd = data.split(" ")[0].upper()
            log_attack(ip, 2525, "SMTP", payload=data[:200])
            if cmd in ("EHLO", "HELO"):
                conn.send(b"250-mail.corp.internal\r\n250 OK\r\n")
            elif cmd == "AUTH":
                conn.send(b"535 Authentication credentials invalid\r\n")
            elif cmd == "QUIT":
                conn.send(b"221 Bye\r\n")
                break
            else:
                conn.send(b"502 Command not implemented\r\n")
    except Exception:
        pass
    finally:
        conn.close()

def smtp_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", SERVICES["SMTP"]["port"]))
    sock.listen(100)
    logging.info(f"SMTP honeypot listening on port {SERVICES['SMTP']['port']}")
    while True:
        try:
            conn, addr = sock.accept()
            threading.Thread(target=handle_smtp_client, args=(conn, addr), daemon=True).start()
        except Exception as e:
            logging.error(f"SMTP error: {e}")

# ─── Web Dashboard ────────────────────────────────────────────────────────────

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sentinel</title>
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#07090f;--s1:#0d1117;--s2:#131922;--s3:#1a2232;
  --b0:rgba(255,255,255,.06);--b1:rgba(255,255,255,.11);
  --blue:#3b82f6;--bdim:#1d4ed8;
  --red:#ef4444;--amber:#f59e0b;--green:#10b981;--violet:#8b5cf6;--cyan:#06b6d4;
  --t1:#f1f5f9;--t2:#94a3b8;--t3:#4a5568;
  --f:"Outfit",sans-serif;--m:"JetBrains Mono",monospace;
}
html,body{height:100%;background:var(--bg);color:var(--t1);font-family:var(--f);overflow-x:hidden}
a{color:inherit;text-decoration:none}

/* ── TOPBAR ── */
.bar{height:52px;display:flex;align-items:center;justify-content:space-between;padding:0 24px;background:var(--s1);border-bottom:1px solid var(--b0);position:sticky;top:0;z-index:99}
.logo{display:flex;align-items:center;gap:10px}
.logo-icon{width:30px;height:30px;border-radius:7px;background:linear-gradient(135deg,#3b82f6,#6366f1);display:flex;align-items:center;justify-content:center;font-size:15px;box-shadow:0 0 16px rgba(99,102,241,.4)}
.logo-name{font-size:1rem;font-weight:800;letter-spacing:-.2px}
.logo-name em{font-style:normal;color:var(--blue)}
.bar-right{display:flex;align-items:center;gap:14px}
.live-pill{display:flex;align-items:center;gap:7px;padding:4px 12px;border-radius:20px;background:rgba(16,185,129,.08);border:1px solid rgba(16,185,129,.18);font-size:.72rem;font-weight:600;color:var(--green)}
.pdot{width:6px;height:6px;border-radius:50%;background:var(--green);animation:blink 2s ease-in-out infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}
#clk{font-family:var(--m);font-size:.72rem;color:var(--t3)}
.refresh-tag{font-family:var(--m);font-size:.65rem;color:var(--t3);padding:3px 8px;border-radius:4px;background:rgba(255,255,255,.04);border:1px solid var(--b0)}

/* ── LAYOUT ── */
.wrap{max-width:1480px;margin:0 auto;padding:20px 24px}

/* ── STAT ROW ── */
.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:16px}
.stat{background:var(--s2);border:1px solid var(--b0);border-radius:10px;padding:16px 18px;position:relative;overflow:hidden;transition:border-color .2s}
.stat:hover{border-color:var(--b1)}
.stat::before{content:"";position:absolute;top:0;left:0;right:0;height:2px;background:var(--c,var(--blue));border-radius:10px 10px 0 0}
.stat-label{font-size:.68rem;font-weight:700;letter-spacing:1px;text-transform:uppercase;color:var(--t3);margin-bottom:8px}
.stat-val{font-size:1.9rem;font-weight:800;line-height:1;letter-spacing:-.5px;color:var(--c,var(--t1));font-variant-numeric:tabular-nums}
.stat-sub{font-size:.65rem;font-family:var(--m);color:var(--t3);margin-top:5px}

/* ── MAIN GRID ── */
.grid-a{display:grid;grid-template-columns:1.6fr 1fr;gap:14px;margin-bottom:14px}
.grid-b{display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px;margin-bottom:14px}
.grid-c{display:grid;grid-template-columns:1.2fr 1fr;gap:14px;margin-bottom:14px}

/* ── CARD ── */
.card{background:var(--s2);border:1px solid var(--b0);border-radius:10px;overflow:hidden}
.card-head{display:flex;align-items:center;justify-content:space-between;padding:12px 16px;border-bottom:1px solid var(--b0);background:rgba(0,0,0,.12)}
.card-title{font-size:.72rem;font-weight:700;letter-spacing:.8px;text-transform:uppercase;color:var(--t2);display:flex;align-items:center;gap:7px}
.card-title .d{width:5px;height:5px;border-radius:50%;background:var(--blue)}
.card-meta{font-family:var(--m);font-size:.67rem;color:var(--t3)}

/* ── FEED ── */
.feed-cols{display:grid;grid-template-columns:145px 112px 62px 145px 1fr;gap:8px;padding:7px 16px;font-size:.6rem;font-weight:700;letter-spacing:1px;text-transform:uppercase;color:var(--t3);border-bottom:1px solid var(--b0);background:rgba(0,0,0,.18)}
.feed-body{height:310px;overflow-y:auto;scrollbar-width:thin;scrollbar-color:var(--s3) transparent}
.feed-body::-webkit-scrollbar{width:3px}
.feed-body::-webkit-scrollbar-thumb{background:var(--s3)}
.row{display:grid;grid-template-columns:145px 112px 62px 145px 1fr;gap:8px;padding:9px 16px;font-size:.72rem;border-bottom:1px solid rgba(255,255,255,.025);transition:background .1s;animation:slide .2s ease}
@keyframes slide{from{opacity:0;transform:translateY(-3px)}to{opacity:1;transform:none}}
.row:hover{background:rgba(255,255,255,.025)}
.row.new{background:rgba(59,130,246,.07)}
.ts{font-family:var(--m);font-size:.65rem;color:var(--t3)}
.ip{font-family:var(--m);font-size:.7rem;color:var(--cyan)}
.cred{font-family:var(--m);font-size:.67rem;color:var(--amber);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.pay{font-size:.7rem;color:var(--t2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

/* ── CHIPS ── */
.chip{display:inline-flex;padding:1px 7px;border-radius:4px;font-size:.62rem;font-weight:700;letter-spacing:.4px}
.SSH   {background:rgba(6,182,212,.12);color:#06b6d4;border:1px solid rgba(6,182,212,.22)}
.FTP   {background:rgba(245,158,11,.12);color:#f59e0b;border:1px solid rgba(245,158,11,.22)}
.HTTP  {background:rgba(16,185,129,.12);color:#10b981;border:1px solid rgba(16,185,129,.22)}
.TELNET{background:rgba(239,68,68,.10);color:#ef4444;border:1px solid rgba(239,68,68,.22)}
.SMTP  {background:rgba(139,92,246,.12);color:#8b5cf6;border:1px solid rgba(139,92,246,.22)}
.MYSQL {background:rgba(251,113,133,.12);color:#fb7185;border:1px solid rgba(251,113,133,.22)}

/* ── CHART BOXES ── */
.chart-box{padding:14px 16px;height:200px}
.chart-box-sm{padding:14px 16px;height:170px}

/* ── IP BARS ── */
.ip-list{padding:2px 0}
.ip-row{display:flex;align-items:center;gap:10px;padding:8px 16px;border-bottom:1px solid rgba(255,255,255,.025)}
.ip-n{font-size:.6rem;font-family:var(--m);color:var(--t3);width:14px}
.ip-body{flex:1;min-width:0}
.ip-addr{font-family:var(--m);font-size:.71rem;color:var(--cyan)}
.ip-bar-row{display:flex;align-items:center;gap:7px;margin-top:3px}
.ip-track{flex:1;height:3px;background:var(--s3);border-radius:2px}
.ip-fill{height:3px;border-radius:2px;background:linear-gradient(90deg,var(--bdim),var(--blue));transition:width .5s}
.ip-cnt{font-family:var(--m);font-size:.64rem;color:var(--t2)}

/* ── CRED TABLE ── */
.cred-table{overflow-y:auto;max-height:220px;scrollbar-width:thin;scrollbar-color:var(--s3) transparent}
.cred-head,.cred-row{display:grid;grid-template-columns:1fr 1fr 56px;gap:8px;padding:8px 16px;font-size:.7rem}
.cred-head{font-size:.6rem;font-weight:700;letter-spacing:1px;text-transform:uppercase;color:var(--t3);border-bottom:1px solid var(--b0);background:rgba(0,0,0,.18)}
.cred-row{border-bottom:1px solid rgba(255,255,255,.025);font-family:var(--m);transition:background .1s}
.cred-row:hover{background:rgba(255,255,255,.02)}
.cu{color:var(--t1)}.cp{color:var(--amber)}.cn{color:var(--t3);text-align:right}

/* ── SENSOR STATUS ── */
.svc-grid{display:grid;grid-template-columns:1fr 1fr;gap:1px;background:var(--b0)}
.svc-cell{background:var(--s2);padding:14px 16px}
.svc-top{display:flex;align-items:center;justify-content:space-between;margin-bottom:4px}
.svc-name{font-size:.82rem;font-weight:700}
.svc-live{display:flex;align-items:center;gap:4px;font-size:.62rem;font-weight:600;color:var(--green);background:rgba(16,185,129,.08);border:1px solid rgba(16,185,129,.15);padding:2px 7px;border-radius:10px}
.svc-port{font-family:var(--m);font-size:.65rem;color:var(--t3)}
.svc-num{font-family:var(--m);font-size:1.05rem;font-weight:800;color:var(--blue);margin-top:4px}

/* ── TOAST ── */
#toast{position:fixed;bottom:20px;right:20px;z-index:999;background:var(--s2);border:1px solid rgba(59,130,246,.4);border-radius:9px;padding:10px 16px;font-size:.78rem;color:var(--t1);box-shadow:0 8px 28px rgba(0,0,0,.5);opacity:0;transform:translateY(6px) scale(.97);transition:all .22s cubic-bezier(.34,1.56,.64,1);pointer-events:none}
#toast.show{opacity:1;transform:none}

@media(max-width:1200px){.stats{grid-template-columns:repeat(3,1fr)}.grid-a,.grid-b,.grid-c{grid-template-columns:1fr}}
</style>
</head>
<body>

<div class="bar">
  <div class="logo">
    <div class="logo-icon">🛡</div>
    <div class="logo-name"><em>Sentinel</em></div>
  </div>
  <div class="bar-right">
    <div class="live-pill"><div class="pdot"></div>All Sensors Live</div>
    <div class="refresh-tag">AUTO ↻ 3s</div>
    <div id="clk">--:--:--</div>
  </div>
</div>

<div class="wrap">

  <!-- STAT CARDS -->
  <div class="stats">
    <div class="stat" style="--c:var(--blue)">
      <div class="stat-label">Total Attacks</div>
      <div class="stat-val" id="v-total">0</div>
      <div class="stat-sub">all time</div>
    </div>
    <div class="stat" style="--c:var(--cyan)">
      <div class="stat-label">Unique IPs</div>
      <div class="stat-val" id="v-ips">0</div>
      <div class="stat-sub">distinct attackers</div>
    </div>
    <div class="stat" style="--c:var(--amber)">
      <div class="stat-label">Last 60 Min</div>
      <div class="stat-val" id="v-hour">0</div>
      <div class="stat-sub" id="v-rate">— / min</div>
    </div>
    <div class="stat" style="--c:var(--green)">
      <div class="stat-label">Credentials</div>
      <div class="stat-val" id="v-creds">0</div>
      <div class="stat-sub">unique pairs captured</div>
    </div>
    <div class="stat" style="--c:var(--violet)">
      <div class="stat-label">Top Target</div>
      <div class="stat-val" id="v-top" style="font-size:1.2rem;padding-top:4px">—</div>
      <div class="stat-sub">most attacked service</div>
    </div>
  </div>

  <!-- ROW A: Live Feed + Donut -->
  <div class="grid-a">
    <div class="card">
      <div class="card-head">
        <div class="card-title"><span class="d"></span>Live Event Stream</div>
        <div class="card-meta" id="feed-count">0 events</div>
      </div>
      <div class="feed-cols"><span>Timestamp</span><span>Source IP</span><span>Service</span><span>Credentials</span><span>Detail</span></div>
      <div class="feed-body" id="feed"></div>
    </div>
    <div class="card">
      <div class="card-head">
        <div class="card-title"><span class="d" style="background:var(--violet)"></span>Attack Distribution</div>
        <div class="card-meta" id="dist-meta">by service</div>
      </div>
      <div class="chart-box"><canvas id="donut"></canvas></div>
    </div>
  </div>

  <!-- ROW B: Timeline + Top IPs + Sensors -->
  <div class="grid-b">
    <div class="card">
      <div class="card-head">
        <div class="card-title"><span class="d" style="background:var(--green)"></span>24h Timeline</div>
        <div class="card-meta" id="peak-label">peak: —</div>
      </div>
      <div class="chart-box-sm"><canvas id="timeline"></canvas></div>
    </div>
    <div class="card">
      <div class="card-head">
        <div class="card-title"><span class="d" style="background:var(--red)"></span>Top Attacker IPs</div>
        <div class="card-meta" id="ip-count">—</div>
      </div>
      <div class="ip-list" id="ip-list"></div>
    </div>
    <div class="card">
      <div class="card-head">
        <div class="card-title"><span class="d" style="background:var(--green)"></span>Sensor Status</div>
        <div class="card-meta">5 / 5 active</div>
      </div>
      <div class="svc-grid" id="svc-grid"></div>
    </div>
  </div>

  <!-- ROW C: Credentials -->
  <div class="card">
    <div class="card-head">
      <div class="card-title"><span class="d" style="background:var(--amber)"></span>Harvested Credentials</div>
      <div class="card-meta" id="cred-meta">0 pairs</div>
    </div>
    <div class="cred-head"><span>Username</span><span>Password</span><span style="text-align:right">Count</span></div>
    <div class="cred-table" id="cred-table"></div>
  </div>

</div>

<div id="toast"></div>

<script>
const $=id=>document.getElementById(id);
const esc=s=>String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
const COLORS={SSH:'#06b6d4',FTP:'#f59e0b',HTTP:'#10b981',TELNET:'#ef4444',SMTP:'#8b5cf6',MYSQL:'#fb7185'};
let D,T,lastN=0;

// Clock
setInterval(()=>$('clk').textContent=new Date().toLocaleTimeString('en-US',{hour12:false}),1000);
$('clk').textContent=new Date().toLocaleTimeString('en-US',{hour12:false});

// Smooth number counter
function count(el,target){
  if(!el)return;
  const cur=parseInt(el.textContent.replace(/,/g,''))||0;
  if(cur===target)return;
  let n=0;const steps=20,inc=(target-cur)/steps;let v=cur;
  const t=setInterval(()=>{n++;v+=inc;el.textContent=Math.round(n<steps?v:target).toLocaleString();if(n>=steps)clearInterval(t)},25);
}

// Service chip
function chip(s){return`<span class="chip ${s}">${s}</span>`}

// Feed
function renderFeed(rows){
  $('feed').innerHTML=rows.map((r,i)=>{
    const ts=r.timestamp.replace('T',' ').slice(0,19);
    const cr=r.username?`${esc(r.username)} / ${esc(r.password||'—')}`:'—';
    return`<div class="row${i===0?' new':''}"><span class="ts">${ts}</span><span class="ip">${r.ip}</span><span>${chip(r.service)}</span><span class="cred">${cr}</span><span class="pay">${esc(r.payload||r.user_agent||'—')}</span></div>`;
  }).join('');
  $('feed-count').textContent=rows.length+' events';
}

// IP list
function renderIPs(ips){
  if(!ips||!ips.length)return;
  const mx=ips[0].count;
  $('ip-list').innerHTML=ips.slice(0,7).map((ip,i)=>`
    <div class="ip-row">
      <div class="ip-n">${i+1}</div>
      <div class="ip-body">
        <div class="ip-addr">${ip.ip}</div>
        <div class="ip-bar-row">
          <div class="ip-track"><div class="ip-fill" style="width:${Math.round(ip.count/mx*100)}%"></div></div>
          <div class="ip-cnt">${ip.count}</div>
        </div>
      </div>
    </div>`).join('');
  $('ip-count').textContent=`${ips.length} actors`;
}

// Creds
function renderCreds(creds){
  $('cred-meta').textContent=creds.length+' pairs';
  $('cred-table').innerHTML=creds.slice(0,40).map(c=>`
    <div class="cred-row">
      <span class="cu">${esc(c.username||'—')}</span>
      <span class="cp">${esc(c.password||'—')}</span>
      <span class="cn">${c.count}</span>
    </div>`).join('');
}

// Services
function renderSvcs(svcs){
  $('svc-grid').innerHTML=svcs.map(s=>`
    <div class="svc-cell">
      <div class="svc-top">
        <div class="svc-name">${s.service}</div>
        <div class="svc-live"><span style="width:4px;height:4px;background:var(--green);border-radius:50%;display:inline-block"></span>LIVE</div>
      </div>
      <div class="svc-port">:${s.port}</div>
      <div class="svc-num">${s.count.toLocaleString()}</div>
    </div>`).join('');
}

// Donut chart
function buildDonut(labels,data){
  const ctx=$('donut').getContext('2d');
  if(D)D.destroy();
  D=new Chart(ctx,{
    type:'doughnut',
    data:{labels,datasets:[{data,backgroundColor:labels.map(l=>COLORS[l]||'#555'),borderColor:'#131922',borderWidth:3}]},
    options:{responsive:true,maintainAspectRatio:false,cutout:'66%',
      plugins:{
        legend:{position:'right',labels:{color:'#94a3b8',font:{family:'Outfit',size:12},padding:12,boxWidth:9,usePointStyle:true}},
        tooltip:{backgroundColor:'#1a2232',borderColor:'rgba(255,255,255,.08)',borderWidth:1,titleColor:'#f1f5f9',bodyColor:'#94a3b8'}
      }
    }
  });
  $('dist-meta').textContent=labels.length+' services';
}

// Timeline chart
function buildTimeline(labels,data){
  const ctx=$('timeline').getContext('2d');
  if(T)T.destroy();
  const mx=Math.max(...data,1);
  $('peak-label').textContent='peak: '+mx+' events';
  T=new Chart(ctx,{
    type:'bar',
    data:{labels,datasets:[{data,backgroundColor:data.map(v=>v===mx?'rgba(59,130,246,.9)':'rgba(59,130,246,.28)'),borderRadius:2,borderSkipped:false}]},
    options:{responsive:true,maintainAspectRatio:false,
      scales:{
        x:{ticks:{color:'#4a5568',font:{family:'JetBrains Mono',size:9},maxRotation:0},grid:{display:false}},
        y:{ticks:{color:'#4a5568',font:{family:'JetBrains Mono',size:9}},grid:{color:'rgba(255,255,255,.035)'}}
      },
      plugins:{legend:{display:false},tooltip:{backgroundColor:'#1a2232',borderColor:'rgba(255,255,255,.08)',borderWidth:1,titleColor:'#f1f5f9',bodyColor:'#94a3b8'}}
    }
  });
}

// Toast
function toast(msg){
  $('toast').textContent=msg;
  $('toast').classList.add('show');
  setTimeout(()=>$('toast').classList.remove('show'),3200);
}

// Main refresh
async function refresh(){
  try{
    const [stats,feed]=await Promise.all([
      fetch('/api/stats').then(r=>r.json()),
      fetch('/api/feed?limit=100').then(r=>r.json())
    ]);

    count($('v-total'),stats.total);
    count($('v-ips'),stats.unique_ips);
    count($('v-hour'),stats.last_hour);
    count($('v-creds'),stats.total_creds);
    $('v-top').textContent=stats.top_service||'—';
    $('v-rate').textContent=(stats.last_hour/60).toFixed(1)+' / min';

    renderFeed(feed);
    renderIPs(stats.top_ips);
    renderCreds(stats.top_creds);
    renderSvcs(stats.services);
    if(stats.service_chart) buildDonut(stats.service_chart.labels,stats.service_chart.data);
    if(stats.timeline)      buildTimeline(stats.timeline.labels,stats.timeline.data);

    if(lastN>0&&stats.total>lastN)
      toast('🚨 '+( stats.total-lastN)+' new attack'+(stats.total-lastN>1?'s':'')+' detected');
    lastN=stats.total;
  }catch(e){console.error(e)}
}

refresh();
setInterval(refresh,3000);
</script>
</body>
</html>
"""
app = Flask(__name__)
logging.getLogger("werkzeug").setLevel(logging.ERROR)

@app.route("/")
def dashboard():
    return DASHBOARD_HTML

@app.route("/api/stats")
def api_stats():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # Totals
    total       = c.execute("SELECT COUNT(*) FROM attacks").fetchone()[0]
    unique_ips  = c.execute("SELECT COUNT(DISTINCT ip) FROM attacks").fetchone()[0]
    total_creds = c.execute("SELECT COUNT(*) FROM attacks WHERE username IS NOT NULL AND password IS NOT NULL").fetchone()[0]
    one_h_ago   = (datetime.now() - timedelta(hours=1)).isoformat()
    last_hour   = c.execute("SELECT COUNT(*) FROM attacks WHERE timestamp > ?", (one_h_ago,)).fetchone()[0]

    # Top service
    top_svc_row = c.execute("SELECT service FROM attacks GROUP BY service ORDER BY COUNT(*) DESC LIMIT 1").fetchone()
    top_service = top_svc_row[0] if top_svc_row else ""

    # Service breakdown
    svc_rows = c.execute("""
        SELECT a.service, COUNT(*) cnt,
               COALESCE((SELECT port FROM attacks b WHERE b.service=a.service LIMIT 1),0) port
        FROM attacks a GROUP BY service ORDER BY cnt DESC
    """).fetchall()
    services = [{"service": r[0], "count": r[1], "port": r[2]} for r in svc_rows]
    service_chart = {
        "labels": [r[0] for r in svc_rows],
        "data":   [r[1] for r in svc_rows],
    }

    # Top IPs
    ip_rows = c.execute("SELECT ip, COUNT(*) cnt FROM attacks GROUP BY ip ORDER BY cnt DESC LIMIT 10").fetchall()
    top_ips = [{"ip": r[0], "count": r[1]} for r in ip_rows]

    # Top credentials
    cred_rows = c.execute("""
        SELECT username, password, COUNT(*) cnt FROM attacks
        WHERE username IS NOT NULL
        GROUP BY username, password ORDER BY cnt DESC LIMIT 30
    """).fetchall()
    top_creds = [{"username": r[0], "password": r[1], "count": r[2]} for r in cred_rows]

    # Timeline (24h)
    timeline_labels, timeline_data = [], []
    for h in range(23, -1, -1):
        t_start = (datetime.now() - timedelta(hours=h+1)).isoformat()
        t_end   = (datetime.now() - timedelta(hours=h)).isoformat()
        cnt = c.execute("SELECT COUNT(*) FROM attacks WHERE timestamp BETWEEN ? AND ?", (t_start, t_end)).fetchone()[0]
        label = (datetime.now() - timedelta(hours=h)).strftime("%H:00")
        timeline_labels.append(label)
        timeline_data.append(cnt)

    conn.close()
    return jsonify({
        "total": total, "unique_ips": unique_ips,
        "last_hour": last_hour, "total_creds": total_creds,
        "top_service": top_service,
        "services": services,
        "top_ips": top_ips,
        "top_creds": top_creds,
        "service_chart": service_chart,
        "timeline": {"labels": timeline_labels, "data": timeline_data},
    })

@app.route("/api/feed")
def api_feed():
    limit = min(int(request.args.get("limit", 50)), 200)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM attacks ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

# ─── Entry Point ──────────────────────────────────────────────────────────────

def start_services():
    listeners = [
        (ssh_listener,    "SSH"),
        (ftp_listener,    "FTP"),
        (http_listener,   "HTTP"),
        (telnet_listener, "Telnet"),
        (smtp_listener,   "SMTP"),
    ]
    for fn, name in listeners:
        if SERVICES.get(name.upper(), {}).get("enabled", False):
            t = threading.Thread(target=fn, daemon=True, name=f"{name}Listener")
            t.start()

def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(LOG_PATH),
            logging.StreamHandler(sys.stdout),
        ],
    )

    print("""
╔══════════════════════════════════════════════════════════╗
║          HoneyTrap Pro — Cybersecurity Honeypot          ║
╠══════════════════════════════════════════════════════════╣
║  Dashboard : http://localhost:5000                       ║
║  Services  : SSH:2222  FTP:2121  HTTP:8888               ║
║              Telnet:2323  SMTP:2525                      ║
║  Database  : honeypot.db                                 ║
║  Logs      : honeypot.log                                ║
╠══════════════════════════════════════════════════════════╣
║  ⚠  FOR EDUCATIONAL / AUTHORIZED USE ONLY               ║
╚══════════════════════════════════════════════════════════╝
""")

    init_db()
    start_services()
    logging.info(f"Web dashboard starting on http://0.0.0.0:{WEB_PORT}")
    app.run(host="0.0.0.0", port=WEB_PORT, debug=False, use_reloader=False)

if __name__ == "__main__":
    main()
