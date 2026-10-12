import sys
import time
import argparse
import httpx


def simulate_brute_force(base_url: str = "http://127.0.0.1:8000", attempts: int = 15, username: str = "admin"):
    print(f"\n[*] Starting simulated Brute-Force attack against {base_url}/api/auth/login")
    print(f"[*] Target account: '{username}', Total attempts: {attempts}")

    passwords = [f"wrong_pass_{i}" for i in range(attempts)]
    with httpx.Client(base_url=base_url, timeout=5.0) as client:
        for idx, pwd in enumerate(passwords, 1):
            try:
                res = client.post("/api/auth/login", json={"username": username, "password": pwd})
                data = res.json()
                print(f"  Attempt {idx:>2}/{attempts}: HTTP {res.status_code} - success={data.get('success')} locked={data.get('is_locked')} - {data.get('message')}")
            except Exception as e:
                print(f"  Attempt {idx:>2}/{attempts} failed to connect: {e}")
            time.sleep(0.1)
    print("[+] Brute-Force simulation finished.\n")


def simulate_direct_auth_events(base_url: str = "http://127.0.0.1:8000", attempts: int = 12, source_ip: str = "192.168.1.99"):
    print(f"\n[*] Injecting normalized authentication events from {source_ip} to {base_url}/api/auth/event")
    with httpx.Client(base_url=base_url, timeout=5.0) as client:
        for i in range(attempts):
            res = client.post("/api/auth/event", json={
                "source_ip": source_ip,
                "account": "root",
                "success": False,
                "event_source": "SIMULATION"
            })
            data = res.json()
            flagged = data.get("threat_flagged")
            print(f"  Event {i+1:>2}: Flagged={flagged}")
            time.sleep(0.05)
    print("[+] Ingestion simulation finished.\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CyberShield Attack Simulator")
    parser.add_argument("--url", default="http://127.0.0.1:8000", help="Backend base URL")
    parser.add_argument("--attack", choices=["brute-force", "auth-inject", "all"], default="brute-force")
    parser.add_argument("--attempts", type=int, default=15)
    args = parser.parse_args()

    if args.attack in ("brute-force", "all"):
        simulate_brute_force(args.url, args.attempts)
    if args.attack in ("auth-inject", "all"):
        simulate_direct_auth_events(args.url, args.attempts)
