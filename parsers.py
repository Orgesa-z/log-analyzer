import re
from datetime import datetime

# Shembull: Nov 08 09:15:22 server sshd[1234]: Failed password for invalid user oracle from 45.155.205.233 port 4455 ssh2
SSH_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"(?P<result>Failed|Accepted)\s+password for\s+(?:invalid user\s+)?(?P<user>\S+)\s+"
    r"from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)"
)

# Shembull: 91.240.118.172 - - [08/Nov/2026:09:15:22 +0000] "GET /.env HTTP/1.1" 404 162 "-" "Nikto/2.5.0"
NGINX_RE = re.compile(
    r'^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>.+?)\s+HTTP/[\d.]+"\s+(?P<status>\d{3})\s+(?P<size>\d+)\s+'
    r'"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)"'
)


def parse_ssh(path, year=None):
    year = year or datetime.now().year
    events = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            m = SSH_RE.match(line)
            if not m:
                continue
            ts = datetime.strptime(
                f"{year} {m['month']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S"
            )
            events.append({
                "time": ts,
                "ip": m["ip"],
                "user": m["user"],
                "success": m["result"] == "Accepted",
                "source": "ssh",
            })
    return events


def parse_nginx(path):
    events = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            m = NGINX_RE.match(line)
            if not m:
                continue
            ts = datetime.strptime(m["time"], "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
            events.append({
                "time": ts,
                "ip": m["ip"],
                "method": m["method"],
                "path": m["path"],
                "status": int(m["status"]),
                "agent": m["agent"],
                "source": "nginx",
            })
    return events


if __name__ == "__main__":
    ssh = parse_ssh("logs/auth.log")
    web = parse_nginx("logs/access.log")
    print(f"SSH: {len(ssh)} ngjarje të parsuara nga 273 rreshta")
    print(f"Nginx: {len(web)} ngjarje të parsuara nga 1069 rreshta")
    print("Shembull SSH:", ssh[0])
    print("Shembull Nginx:", web[0])