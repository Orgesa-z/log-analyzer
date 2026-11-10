import re
from datetime import datetime

# Formati klasik: Nov 08 09:15:22 server sshd[1234]: Failed password for invalid user oracle from 1.2.3.4 port 4455 ssh2
SSH_CLASSIC = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+sshd(?:-session)?\[\d+\]:\s+"
    r"(?P<result>Failed|Accepted)\s+password for\s+(?:invalid user\s+)?(?P<user>\S+)\s+"
    r"from\s+(?P<ip>[0-9a-fA-F.:]+)"
)

# Formati modern (rsyslog ISO): 2026-11-10T06:44:15.170038+01:00 host sshd-session[1819]: Invalid user fakeuser14 from 127.0.0.1 port 40118
SSH_ISO = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?\s+\S+\s+sshd(?:-session)?\[\d+\]:\s+"
    r"(?:"
    r"(?P<result>Failed|Accepted)\s+password for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>[0-9a-fA-F.:]+)"
    r"|"
    r"Invalid user\s+(?P<iuser>\S+)\s+from\s+(?P<iip>[0-9a-fA-F.:]+)"
    r")"
)

NGINX_RE = re.compile(
    r'^(?P<ip>[0-9a-fA-F.:]+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>.+?)\s+HTTP/[\d.]+"\s+(?P<status>\d{3})\s+(?P<size>\d+)\s+'
    r'"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)"'
)


def parse_ssh(path, year=None):
    year = year or datetime.now().year
    events = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = SSH_ISO.match(line)
            if m:
                ts = datetime.strptime(m["ts"], "%Y-%m-%dT%H:%M:%S")
                if m["iuser"]:
                    events.append({"time": ts, "ip": m["iip"], "user": m["iuser"],
                                   "success": False, "source": "ssh"})
                else:
                    events.append({"time": ts, "ip": m["ip"], "user": m["user"],
                                   "success": m["result"] == "Accepted", "source": "ssh"})
                continue
            m = SSH_CLASSIC.match(line)
            if m:
                ts = datetime.strptime(
                    f"{year} {m['month']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S")
                events.append({"time": ts, "ip": m["ip"], "user": m["user"],
                               "success": m["result"] == "Accepted", "source": "ssh"})
    return events


def parse_nginx(path):
    events = []
    with open(path, encoding="utf-8", errors="replace") as f:
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
    print(f"SSH: {len(ssh)} ngjarje, Nginx: {len(web)} ngjarje")