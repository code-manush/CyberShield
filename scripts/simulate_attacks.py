import sys
import time
import argparse
import httpx


def trigger_api_attack(base_url: str, attack_type: str, auto_enforce: bool = False):
    print(f"\n[*] Triggering live attack '{attack_type}' via CyberShield API ({base_url})...")
    with httpx.Client(base_url=base_url, timeout=10.0) as client:
        try:
            res = client.post("/api/simulation/start", json={
                "attack_type": attack_type,
                "auto_enforce": auto_enforce
            })
            if res.status_code == 200:
                data = res.json()
                print(f"[+] Attack launched: {data.get('attack_type')} from {data.get('source_ip')} -> {data.get('target_ip')}")
                print("[*] Streaming live progress:")
                while True:
                    time.sleep(0.5)
                    st = client.get("/api/simulation/status").json()
                    step = st.get("current_step", "")
                    progress = st.get("progress_percent", 0)
                    print(f"    [{progress:>3}%] {step}")
                    if not st.get("is_attacking"):
                        print("[+] Attack run concluded.\n")
                        break
            else:
                print(f"[-] API error {res.status_code}: {res.text}")
        except Exception as e:
            print(f"[-] Failed to trigger attack: {e}")


def simulate_brute_force_direct(base_url: str = "http://127.0.0.1:8000", attempts: int = 15, username: str = "admin"):
    print(f"\n[*] Direct HTTP Brute-Force against {base_url}/api/auth/login")
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
    print("[+] Direct brute-force finished.\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CyberShield Active Attack Simulator")
    parser.add_argument("--url", default="http://127.0.0.1:8000", help="Backend base URL")
    parser.add_argument(
        "--attack",
        choices=["port-scan", "syn-flood", "brute-force", "multi-vector", "auth-direct"],
        default="port-scan",
        help="Type of attack to launch"
    )
    parser.add_argument("--enforce", action="store_true", help="Auto-enable ENFORCE mode to demonstrate firewall auto-blocking")
    parser.add_argument("--attempts", type=int, default=15, help="Attempts for brute force")
    args = parser.parse_args()

    mapping = {
        "port-scan": "PORT_SCAN",
        "syn-flood": "SYN_FLOOD",
        "brute-force": "BRUTE_FORCE",
        "multi-vector": "MULTI_VECTOR"
    }

    if args.attack == "auth-direct":
        simulate_brute_force_direct(args.url, args.attempts)
    else:
        attack_type = mapping[args.attack]
        trigger_api_attack(args.url, attack_type, auto_enforce=args.enforce)
