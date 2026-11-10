import json
import re
import sqlite3
from collections import defaultdict
from datetime import timedelta

from notify import send_email
from parsers import parse_ssh, parse_nginx

NOTIFIED_FILE = "notified.json"

# ---- Pragjet (mund t'i ndryshosh) ----
SSH_FAILS_THRESHOLD = 10           # N login të dështuar...
SSH_WINDOW = timedelta(minutes=5)  # ...brenda X minutash
SCAN_404_THRESHOLD = 15            # N kërkesa 404 nga e njëjta IP
LOGIN_POST_THRESHOLD = 15          # N POST /login me 401
SUSPICIOUS_PATHS = ["/wp-login.php", "/.env", "/phpmyadmin", "/.git", "/xmlrpc.php",
                    "/config.php", "/backup.sql", "/server-status"]
INJECTION_PATTERNS = re.compile(
    r"(union\s+select|or\s+'1'\s*=\s*'1|<script|\.\./|etc/passwd|sleep\(|--\s*$)",
    re.IGNORECASE,
)
BAD_AGENTS = ["sqlmap", "nikto", "nmap", "masscan", "python-requests", "curl"]


def alert(alerts, severity, kind, ip, details, time):
    alerts.append({
        "severity": severity, "kind": kind, "ip": ip,
        "details": details, "time": time.isoformat(),
    })


def detect_ssh_bruteforce(events, alerts):
    fails = defaultdict(list)
    successes = defaultdict(list)
    for e in events:
        (successes if e["success"] else fails)[e["ip"]].append(e)

    for ip, evs in fails.items():
        evs.sort(key=lambda x: x["time"])
        # dritare rrëshqitëse: a ka >= N dështime brenda SSH_WINDOW?
        left = 0
        for right in range(len(evs)):
            while evs[right]["time"] - evs[left]["time"] > SSH_WINDOW:
                left += 1
            if right - left + 1 >= SSH_FAILS_THRESHOLD:
                users = {x["user"] for x in evs}
                alert(alerts, "HIGH", "SSH brute-force", ip,
                      f"{len(evs)} login të dështuar, {len(users)} përdorues të provuar",
                      evs[left]["time"])
                # kontrollo nëse pas sulmit ka pasur login të suksesshëm
                for s in successes.get(ip, []):
                    if s["time"] >= evs[left]["time"]:
                        alert(alerts, "CRITICAL", "Brute-force i SUKSESSHËM", ip,
                              f"Login i pranuar si '{s['user']}' pas {len(evs)} dështimesh!",
                              s["time"])
                        break
                break


def detect_web(events, alerts):
    by_ip = defaultdict(list)
    for e in events:
        by_ip[e["ip"]].append(e)

    for ip, evs in by_ip.items():
        evs.sort(key=lambda x: x["time"])

        # 1) Skanim: shumë 404 ose path të dyshimta
        n404 = [e for e in evs if e["status"] == 404]
        sus = [e for e in evs if any(p in e["path"] for p in SUSPICIOUS_PATHS)]
        if len(n404) >= SCAN_404_THRESHOLD or len(sus) >= 5:
            alert(alerts, "MEDIUM", "Skanim web", ip,
                  f"{len(n404)} kërkesa 404, {len(sus)} path të dyshimta (p.sh. {sus[0]['path'] if sus else '-'})",
                  evs[0]["time"])

        # 2) Injection (SQLi / XSS / path traversal)
        inj = [e for e in evs if INJECTION_PATTERNS.search(e["path"])]
        if inj:
            alert(alerts, "HIGH", "Injection (SQLi/XSS)", ip,
                  f"{len(inj)} kërkesa me payload, p.sh. {inj[0]['path'][:60]}",
                  inj[0]["time"])

        # 3) Brute-force në login web
        posts = [e for e in evs if e["method"] == "POST" and e["status"] in (401, 403)]
        if len(posts) >= LOGIN_POST_THRESHOLD:
            alert(alerts, "HIGH", "Brute-force web login", ip,
                  f"{len(posts)} përpjekje të dështuara në /login", posts[0]["time"])

        # 4) User-agent i dyshimtë
        agents = {e["agent"] for e in evs if any(b in e["agent"].lower() for b in BAD_AGENTS)}
        if agents:
            alert(alerts, "LOW", "User-agent i dyshimtë", ip,
                  f"Agent: {', '.join(sorted(agents))}", evs[0]["time"])


def save_alerts(alerts, db="alerts.db"):
    con = sqlite3.connect(db)
    con.execute("DROP TABLE IF EXISTS alerts")
    con.execute("""CREATE TABLE alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        severity TEXT, kind TEXT, ip TEXT, details TEXT, time TEXT)""")
    con.executemany(
        "INSERT INTO alerts (severity, kind, ip, details, time) VALUES (:severity,:kind,:ip,:details,:time)",
        alerts,
    )
    con.commit()
    con.close()


def notify_critical(alerts):
    """Dërgon email vetëm për alarme CRITICAL që nuk janë njoftuar më parë."""
    try:
        with open(NOTIFIED_FILE) as f:
            seen = set(json.load(f))
    except (FileNotFoundError, json.JSONDecodeError):
        seen = set()

    for a in alerts:
        if a["severity"] != "CRITICAL":
            continue
        key = f"{a['ip']}|{a['kind']}|{a['time']}"
        if key in seen:
            continue
        ok = send_email(
            f"[CRITICAL] {a['kind']} nga {a['ip']}",
            f"{a['details']}\n\nKoha: {a['time']}\nIP: {a['ip']}\n\n"
            f"Kontrollo dashboard-in dhe konsidero bllokimin e kësaj IP.",
        )
        if ok:
            seen.add(key)

    with open(NOTIFIED_FILE, "w") as f:
        json.dump(sorted(seen), f)


def run(log_dir="logs"):
    alerts = []
    detect_ssh_bruteforce(parse_ssh(f"{log_dir}/auth.log"), alerts)
    detect_web(parse_nginx(f"{log_dir}/access.log"), alerts)
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    alerts.sort(key=lambda a: order[a["severity"]])
    save_alerts(alerts)
    notify_critical(alerts)
    return alerts


if __name__ == "__main__":
    alerts = run()
    print(f"\n{len(alerts)} alarme u gjetën:\n")
    for a in alerts:
        print(f"[{a['severity']:8}] {a['kind']:26} {a['ip']:16} {a['details']}")