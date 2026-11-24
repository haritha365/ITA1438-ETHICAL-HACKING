"""
===================================================================================
Adaptive Authentication Security System (AASS) - Terminal Attack Simulator CLI
Module 2: Real-Time Brute-Force Attack Detection & Threat Mitigation
Demonstration & Defensive Testing Tool
===================================================================================

This interactive CLI simulation tool demonstrates the real-time detection,
dynamic risk scoring, CAPTCHA challenge triggering, and automated defensive
account lockouts / IP quarantines implemented in SentinelShield AASS.
"""

import sys
import time
import json
import random
import urllib.request
import urllib.error

# ANSI Color Codes for terminal visual fidelity
CYAN = '\033[96m'
BLUE = '\033[94m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
MAGENTA = '\033[95m'
BOLD = '\033[1m'
DIM = '\033[2m'
RESET = '\033[0m'

DEFAULT_SERVER_URL = "http://127.0.0.1:5000"

COMMON_PASSWORDS = [
    "admin123", "password", "12345678", "qwerty", "welcome1",
    "letmein", "football", "dragon", "master", "shadow",
    "superman", "trustno1", "correcthorse", "admin@2024", "P@ssw0rd2024"
]

SPOOFED_IPS = [
    ("45.154.255.89", "St. Petersburg, RU", "Hydra/9.5 Brute-Forcer"),
    ("185.220.101.5", "Frankfurt, DE (Tor Exit)", "Python-requests/2.31"),
    ("194.26.29.112", "Amsterdam, NL", "Medusa/2.2 Network Prober"),
    ("91.240.118.234", "Kyiv, UA", "Custom Go Botnet"),
    ("109.205.213.6", "Bucharest, RO", "OpenBullet/1.4.4")
]

TARGET_ACCOUNTS = ["admin", "finance_mgr", "sec_analyst", "threat_hunter", "demo", "sarah_k"]


def print_banner():
    print(f"{CYAN}{BOLD}")
    print("*" * 72)
    print("   SENTINEL SHIELD - ADAPTIVE ATTACK SIMULATION TERMINAL")
    print("   Real-Time Brute-Force Attack Generation & Defense Testing")
    print("*" * 72)
    print(f"{RESET}")
    print(f"{BLUE}Target Server:{RESET} {DEFAULT_SERVER_URL}")
    print(f"{MAGENTA}Module 1:{RESET} Adaptive User Authentication Core")
    print(f"{MAGENTA}Module 2:{RESET} Real-Time Brute-Force Defense Engine")
    print("-" * 72)


def send_login_request(server_url, username, password, ip=None, user_agent=None, captcha_solution=None, captcha_token=None):
    """Sends HTTP POST request to /api/auth/login with spoofed network telemetry."""
    endpoint = f"{server_url}/api/auth/login"
    payload = {
        "username": username,
        "password": password
    }
    if captcha_solution and captcha_token:
        payload["captchaSolution"] = captcha_solution
        payload["captchaToken"] = captcha_token

    data = json.dumps(payload).encode('utf-8')
    headers = {
        'Content-Type': 'application/json',
        'User-Agent': user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
    }
    if ip:
        headers['X-Forwarded-For'] = ip

    req = urllib.request.Request(endpoint, data=data, headers=headers, method='POST')

    start_time = time.time()
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            latency = int((time.time() - start_time) * 1000)
            res_body = json.loads(response.read().decode('utf-8'))
            return response.status, res_body, latency
    except urllib.error.HTTPError as e:
        latency = int((time.time() - start_time) * 1000)
        try:
            res_body = json.loads(e.read().decode('utf-8'))
        except Exception:
            res_body = {"error": str(e)}
        return e.code, res_body, latency
    except Exception as e:
        return 0, {"error": str(e)}, 0


def check_health(server_url):
    """Verifies server connectivity and reports security engine mode."""
    try:
        req = urllib.request.Request(f"{server_url}/api/health", headers={'User-Agent': 'AASS-CLI-Probe'})
        with urllib.request.urlopen(req, timeout=4) as response:
            data = json.loads(response.read().decode('utf-8'))
            return True, data
    except Exception as e:
        return False, str(e)


def run_targeted_brute_force(server_url):
    """Simulates a targeted dictionary attack against a single account until lockout."""
    print(f"\n{YELLOW}{BOLD}=== Scenario 1: Targeted Single-Account Brute-Force Attack ==={RESET}")
    username = input(f"{CYAN}Enter target username (default: 'finance_mgr'): {RESET}").strip() or "finance_mgr"
    attacker_ip = "185.220.101.5"
    attacker_agent = "Hydra/9.5 (Kali Linux 2024.1)"

    print(f"{DIM}Attacking Target: {BOLD}{username}{RESET}{DIM} from IP: {BOLD}{attacker_ip}{RESET}")
    print(f"{DIM}Sending automated credential probes until defensive lockout is triggered...{RESET}\n")

    for idx, pwd in enumerate(COMMON_PASSWORDS, start=1):
        status_code, body, latency = send_login_request(
            server_url=server_url,
            username=username,
            password=pwd,
            ip=attacker_ip,
            user_agent=attacker_agent
        )

        risk = body.get('risk_score', 0)
        status_str = body.get('status', 'UNKNOWN')

        if status_code == 200:
            print(f"[{idx:02d}] {GREEN}SUCCESS (200){RESET} | Pwd: '{pwd}' | Risk: {risk}% | Status: {status_str} ({latency}ms)")
            break
        elif status_code == 400:
            print(f"[{idx:02d}] {YELLOW}CAPTCHA CHALLENGE (400){RESET} | Pwd: '{pwd}' | Risk: {risk}% | Msg: {body.get('message', '')} ({latency}ms)")
            print(f"     {MAGENTA}--> Module 2: Anti-Bot CAPTCHA triggered. Attacker lacks token, continuing brute force...{RESET}")
        elif status_code == 401:
            print(f"[{idx:02d}] {RED}AUTH FAILED (401){RESET} | Pwd: '{pwd}' | Risk: {risk}% | Remaining Attempts: {body.get('remainingAttempts', 'N/A')} ({latency}ms)")
        elif status_code == 403:
            print(f"[{idx:02d}] {RED}{BOLD}DEFENSIVE LOCKOUT TRIGGERED (403){RESET} | Pwd: '{pwd}' | Risk: {risk}% | Status: {status_str} ({latency}ms)")
            print(f"\n{GREEN}{BOLD}[DEFENSE ACTIVATED]{RESET} Account [{username}] has been automatically locked for 10 minutes.")
            print(f"{GREEN}[ALERT DISPATCHED]{RESET} SSE event broadcast to admin dashboard in real-time.")
            break
        else:
            print(f"[{idx:02d}] HTTP {status_code} | Msg: {body} ({latency}ms)")

        time.sleep(0.4)


def run_distributed_credential_stuffing(server_url):
    """Simulates distributed botnet credential stuffing across multiple rotating IPs."""
    print(f"\n{MAGENTA}{BOLD}=== Scenario 2: Distributed Botnet Credential Stuffing ==={RESET}")
    print(f"{DIM}Simulating multi-node distributed attack targeting multiple accounts simultaneously...{RESET}\n")

    attempts = 15
    for i in range(1, attempts + 1):
        ip_info = random.choice(SPOOFED_IPS)
        ip_addr, geo, agent = ip_info
        target = random.choice(TARGET_ACCOUNTS)
        pwd = random.choice(COMMON_PASSWORDS)

        status_code, body, latency = send_login_request(
            server_url=server_url,
            username=target,
            password=pwd,
            ip=ip_addr,
            user_agent=agent
        )

        risk = body.get('risk_score', 0)
        status = body.get('status', 'PROBE')

        badge_color = RED if status_code in (401, 403) else (YELLOW if status_code == 400 else GREEN)
        print(f"[{i:02d}/{attempts}] Node: {CYAN}{ip_addr:<15}{RESET} ({geo:<22}) -> Target: {BOLD}{target:<12}{RESET} | Status: {badge_color}{status:<18}{RESET} | Risk: {risk:>2}% ({latency}ms)")

        if status == 'IP_BLOCKED':
            print(f"     {RED}{BOLD}[DEFENSE ACTIVATED]{RESET} IP [{ip_addr}] auto-quarantined on threat boundary.")

        time.sleep(0.35)

    print(f"\n{GREEN}{BOLD}[WAVE COMPLETE]{RESET} Distributed attack wave simulated. Check the Admin Dashboard and Threat Radar.")


def run_high_frequency_post_storm(server_url):
    """Simulates a fast POST storm from an aggressive attacking script."""
    print(f"\n{RED}{BOLD}=== Scenario 3: High-Frequency POST Storm (IP Auto-Quarantine Test) ==={RESET}")
    attacker_ip = "45.154.255.89"
    attacker_geo = "St. Petersburg, RU"
    print(f"{DIM}Rapidly flooding /api/auth/login with rapid probes from {attacker_ip} ({attacker_geo})...{RESET}\n")

    for i in range(1, 10):
        target = random.choice(["admin", "root", "administrator"])
        pwd = f"badpass_{random.randint(1000, 9999)}"

        status_code, body, latency = send_login_request(
            server_url=server_url,
            username=target,
            password=pwd,
            ip=attacker_ip,
            user_agent="Go-http-client/1.1 (BruteFlood 2.0)"
        )

        risk = body.get('risk_score', 0)
        status = body.get('status', 'PROBE')
        print(f"[Burst #{i}] Code: {status_code} | Target: {target:<14} | Risk: {risk}% | Status: {status}")

        if status == 'IP_BLOCKED' or body.get('ip_blocked'):
            print(f"\n{GREEN}{BOLD}[DEFENSE TRIGGERED]{RESET} Malicious IP [{attacker_ip}] reached velocity limit.")
            print(f"{GREEN}[QUARANTINE ENFORCED]{RESET} IP blocked for 60 minutes. Check IP Monitoring Page (`ip_monitoring.html`).")
            break

        time.sleep(0.15)


def run_diagnostic_check(server_url):
    """Checks the health and settings of the running system."""
    print(f"\n{BLUE}{BOLD}=== System Health & Security Diagnostic ==={RESET}")
    ok, data = check_health(server_url)
    if not ok:
        print(f"{RED}[OFFLINE] Could not connect to {server_url}. Is 'python app.py' running?{RESET}")
        print(f"Error details: {data}")
        return

    print(f"{GREEN}[ONLINE]{RESET} Connected to AASS Security Server v{data.get('version', '2.4.0')}")
    print(f"   - Database Engine: {CYAN}{data.get('database', 'SQLite Fallback')}{RESET}")
    print(f"   - Password Hasher: {CYAN}{data.get('hasher', 'Argon2id + Bcrypt')}{RESET}")
    print(f"   - Adaptive Engine: {GREEN}ACTIVE (Module 2 Real-Time Defense){RESET}")

    # Fetch settings
    try:
        req = urllib.request.Request(f"{server_url}/api/settings", headers={'User-Agent': 'AASS-CLI-Probe'})
        with urllib.request.urlopen(req, timeout=4) as response:
            s_data = json.loads(response.read().decode('utf-8'))
            if s_data.get('success'):
                s = s_data['settings']
                print(f"\n{BOLD}Active Security Thresholds:{RESET}")
                print(f"   * Max Failed Attempts:   {s.get('max_failed_attempts')} attempts")
                print(f"   * Window Minutes:        {s.get('login_window_minutes')} minutes")
                print(f"   * Lockout Duration:      {s.get('lockout_duration_minutes')} minutes")
                print(f"   * Suspicious Threshold:  {s.get('suspicious_threshold')}% risk")
                print(f"   * CAPTCHA Trigger:       {s.get('captcha_trigger_threshold')} failed attempts")
                print(f"   * Auto IP Blocking:      {s.get('auto_block_ip')}")
    except Exception as e:
        print(f"{YELLOW}[WARN] Could not retrieve active settings: {e}{RESET}")


def interactive_menu():
    print_banner()

    server_url = DEFAULT_SERVER_URL
    ok, _ = check_health(server_url)
    if not ok:
        print(f"{YELLOW}[NOTICE] Server is currently not detected on {server_url}.{RESET}")
        print(f"{DIM}Tip: Start the server in another terminal via: {BOLD}python app.py{RESET}\n")

    while True:
        print(f"\n{CYAN}{BOLD}--- Simulation Menu ---{RESET}")
        print("  [1] Single-Account Targeted Brute-Force Attack (Triggers CAPTCHA & Lockout)")
        print("  [2] Distributed Botnet Credential Stuffing (Multi-IP Attack Wave)")
        print("  [3] Rapid POST Storm (Triggers Automated IP Quarantine)")
        print("  [4] Run System Diagnostic & Check Security Thresholds")
        print("  [5] Change Target Server URL")
        print("  [0] Exit Simulator")

        try:
            choice = input(f"\n{BOLD}Select an action [0-5]: {RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            break

        if choice == '1':
            run_targeted_brute_force(server_url)
        elif choice == '2':
            run_distributed_credential_stuffing(server_url)
        elif choice == '3':
            run_high_frequency_post_storm(server_url)
        elif choice == '4':
            run_diagnostic_check(server_url)
        elif choice == '5':
            new_url = input(f"Enter server URL (e.g. http://127.0.0.1:5000): ").strip()
            if new_url:
                server_url = new_url
                print(f"Updated server URL to: {server_url}")
        elif choice == '0':
            print(f"{GREEN}Session ended. Thank you for testing SentinelShield AASS.{RESET}")
            break
        else:
            print(f"{RED}Invalid option. Please choose between 0 and 5.{RESET}")


if __name__ == "__main__":
    interactive_menu()

