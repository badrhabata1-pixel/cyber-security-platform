"""Generate deterministic realistic SSH traffic and its ground-truth attack labels."""
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(8002)
out = Path(__file__).with_name("sample_auth.log")
truth = Path(__file__).with_name("truth.json")
base = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(hours=6)
lines, attacks = [], []

def ssh_line(at, message):
    return f"{at.strftime('%b %d %H:%M:%S')} srv01 sshd[{random.randint(100,9999)}]: {message}"

for i in range(180):
    at = base + timedelta(minutes=i * 2)
    ip = random.choice(["192.0.2.44", "198.51.100.18", "203.0.113.88"])
    user = random.choice(["alice", "bob", "deploy"])
    lines.append(ssh_line(at, f"Accepted password for {user} from {ip} port 4321 ssh2"))

brute_ip = "203.0.113.5"
for i in range(30):
    at = base + timedelta(minutes=15, seconds=i * 8)
    lines.append(ssh_line(at, f"Failed password for root from {brute_ip} port {4000+i} ssh2"))
attacks.append({"type": "brute_force", "ip": brute_ip, "events": 30})

spray_ips = ["198.51.100.22", "203.0.113.77", "192.0.2.222"]
for ip in spray_ips:
    at = base + timedelta(hours=2, minutes=spray_ips.index(ip))
    lines.append(ssh_line(at, f"Invalid user finance from {ip} port 5555"))
attacks.append({"type": "password_spraying", "username": "finance", "ips": spray_ips, "events": 3})
lines.append("this intentionally malformed log line exercises parser resilience")
random.shuffle(lines)
out.write_text("\n".join(lines) + "\n", encoding="utf-8")
truth.write_text(json.dumps({"generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "expected": {"events": 213, "unparsed": 1, "failed_logins": 33}, "attacks": attacks}, indent=2), encoding="utf-8")
print(f"Wrote {out} and {truth}")
