#!/usr/bin/env python3
"""
attack_demo.py  -  SecureTx Attack Simulator
Run AFTER: python app.py
Then open: http://127.0.0.1:5000/security
Login:     admin@example.com / adminpass
"""

import requests, time, sys, re

BASE = "http://127.0.0.1:5000"

R="\033[91m"; G="\033[92m"; Y="\033[93m"; C="\033[96m"; W="\033[97m"; B="\033[1m"; X="\033[0m"

ATTACKS = [
    {"id":"brute_force", "name":"Brute-Force Login",    "sev":"CRITICAL", "c":R},
    {"id":"velocity",    "name":"Transaction Velocity", "sev":"HIGH",     "c":Y},
    {"id":"replay",      "name":"Replay Attack",        "sev":"CRITICAL", "c":R},
    {"id":"amount",      "name":"Amount Anomaly",       "sev":"MEDIUM",   "c":Y},
    {"id":"otp_bomb",    "name":"OTP Bombing",          "sev":"HIGH",     "c":Y},
    {"id":"large_tx",    "name":"Large Transaction",    "sev":"HIGH",     "c":Y},
]

def check_server():
    try: requests.get(BASE, timeout=3); return True
    except: return False

def trigger(attack_id):
    try:
        r = requests.post(
            f"{BASE}/demo/attack",
            json={"type": attack_id, "email": "user@example.com", "ip": "10.0.0.1"},
            timeout=5
        )
        return r.json().get("status") == "ok"
    except Exception as e:
        print(f"  {R}Error: {e}{X}"); return False

def real_brute_force():
    s = requests.Session()
    print(f"  {Y}Sending 5 real wrong-password attempts...{X}")
    try:
        page  = s.get(f"{BASE}/login", timeout=3)
        match = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
        if not match: print(f"  {R}No CSRF token found{X}"); return
        token = match.group(1)
        for i in range(5):
            s.post(f"{BASE}/login", data={"email":"user@example.com",
                "password":f"wrong{i}","csrf_token":token}, timeout=3)
            page  = s.get(f"{BASE}/login", timeout=3)
            m     = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
            if m: token = m.group(1)
            print(f"  Attempt {i+1}/5"); time.sleep(0.3)
        print(f"  {G}Done!{X}")
    except Exception as e:
        print(f"  {R}Error: {e}{X}")

print(f"\n{R}{B} SecureTx Attack Demo Simulator {X}\n")

if not check_server():
    print(f"{R}App not running! Run: python app.py{X}"); sys.exit(1)
print(f"{G}Server online!{X}")
print(f"{C}Alerts will appear at: {BASE}/security{X}")
print(f"Login: admin@example.com / adminpass\n")
input(f"{Y}Press ENTER to start...{X}\n")

results = []
for i, atk in enumerate(ATTACKS):
    print(f"{atk['c']}{B}[{i+1}/6] {atk['name']} — {atk['sev']}{X}", end="  ")
    ok = trigger(atk["id"])
    print(f"{G}ALERT CREATED!{X}" if ok else f"{R}FAILED{X}")
    results.append((atk["name"], ok))
    time.sleep(0.6)

print(f"\n{Y}{B}[BONUS] Real HTTP brute force:{X}")
real_brute_force()

passed = sum(1 for _,ok in results if ok)
print(f"\n{W}{B}{'='*44}")
print(f"  DONE: {passed}/6 alerts triggered")
print(f"{'='*44}{X}")
print(f"\n{C}Now open: {W}{BASE}/security{X}")
print(f"Login as: {W}admin@example.com / adminpass{X}\n")