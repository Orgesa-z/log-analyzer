import random
from datetime import datetime, timedelta

random.seed(42)

NORMAL_IPS = [f"192.168.1.{i}" for i in range(10, 40)]
ATTACKER_SSH = ["45.155.205.233", "185.220.101.45", "103.145.12.88"]
ATTACKER_WEB = ["91.240.118.172", "194.26.135.60", "141.98.11.5"]
USERS_REAL = ["orgesa", "admin", "deploy"]
USERS_FAKE = ["root", "admin", "test", "oracle", "ubuntu", "postgres", "user", "pi"]

NORMAL_PATHS = ["/", "/index.html", "/about", "/contact", "/products",
                "/static/app.js", "/static/style.css", "/api/items", "/login"]
SCAN_PATHS = ["/wp-login.php", "/.env", "/phpmyadmin/", "/admin", "/.git/config",
              "/xmlrpc.php", "/config.php", "/backup.sql", "/server-status"]
ATTACK_PAYLOADS = [
    "/search?q=' OR '1'='1",
    "/products?id=1 UNION SELECT username,password FROM users--",
    "/search?q=<script>alert(1)</script>",
    "/download?file=../../../../etc/passwd",
]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Safari/604.1",
]
BAD_AGENTS = ["sqlmap/1.7", "Nikto/2.5.0", "python-requests/2.31", "curl/8.4.0"]

start = datetime.now() - timedelta(hours=6)


def ssh_ts(t):
    return t.strftime("%b %d %H:%M:%S").replace(" 0", "  ", 1)


def nginx_ts(t):
    return t.strftime("%d/%b/%Y:%H:%M:%S +0000")


def gen_auth():
    events = []
    # Normal successful logins
    for _ in range(60):
        t = start + timedelta(seconds=random.randint(0, 6 * 3600))
        ip = random.choice(NORMAL_IPS)
        user = random.choice(USERS_REAL)
        port = random.randint(30000, 65000)
        pid = random.randint(1000, 30000)
        events.append((t, f"{ssh_ts(t)} server sshd[{pid}]: Accepted password for {user} from {ip} port {port} ssh2"))
    # A few normal typos
    for _ in range(8):
        t = start + timedelta(seconds=random.randint(0, 6 * 3600))
        ip = random.choice(NORMAL_IPS)
        user = random.choice(USERS_REAL)
        pid = random.randint(1000, 30000)
        events.append((t, f"{ssh_ts(t)} server sshd[{pid}]: Failed password for {user} from {ip} port {random.randint(30000, 65000)} ssh2"))
    # Brute-force attacks
    for ip in ATTACKER_SSH:
        burst_start = start + timedelta(minutes=random.randint(30, 300))
        attempts = random.randint(40, 120)
        for i in range(attempts):
            t = burst_start + timedelta(seconds=i * random.randint(1, 4))
            user = random.choice(USERS_FAKE)
            pid = random.randint(1000, 30000)
            port = random.randint(30000, 65000)
            if user in ("root", "admin"):
                events.append((t, f"{ssh_ts(t)} server sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2"))
            else:
                events.append((t, f"{ssh_ts(t)} server sshd[{pid}]: Failed password for invalid user {user} from {ip} port {port} ssh2"))
        # Attacker finally gets in (for one IP)
    t = start + timedelta(hours=5, minutes=20)
    ip = ATTACKER_SSH[0]
    events.append((t, f"{ssh_ts(t)} server sshd[9999]: Accepted password for root from {ip} port 44321 ssh2"))
    events.sort(key=lambda e: e[0])
    with open("logs/auth.log", "w") as f:
        for _, line in events:
            f.write(line + "\n")
    print(f"auth.log: {len(events)} rreshta")


def gen_nginx():
    events = []
    # Normal traffic
    for _ in range(800):
        t = start + timedelta(seconds=random.randint(0, 6 * 3600))
        ip = random.choice(NORMAL_IPS)
        path = random.choice(NORMAL_PATHS)
        status = random.choices([200, 304, 404], weights=[90, 8, 2])[0]
        size = random.randint(200, 50000)
        ua = random.choice(USER_AGENTS)
        events.append((t, f'{ip} - - [{nginx_ts(t)}] "GET {path} HTTP/1.1" {status} {size} "-" "{ua}"'))
    # Scanners
    for ip in ATTACKER_WEB:
        burst_start = start + timedelta(minutes=random.randint(20, 300))
        ua = random.choice(BAD_AGENTS)
        for i in range(random.randint(30, 80)):
            t = burst_start + timedelta(seconds=i * random.randint(1, 3))
            path = random.choice(SCAN_PATHS)
            events.append((t, f'{ip} - - [{nginx_ts(t)}] "GET {path} HTTP/1.1" 404 162 "-" "{ua}"'))
    # Injection attempts
    for ip in ATTACKER_WEB[:2]:
        for _ in range(random.randint(8, 15)):
            t = start + timedelta(seconds=random.randint(0, 6 * 3600))
            payload = random.choice(ATTACK_PAYLOADS)
            events.append((t, f'{ip} - - [{nginx_ts(t)}] "GET {payload} HTTP/1.1" {random.choice([400, 403, 500])} 300 "-" "sqlmap/1.7"'))
    # Brute-force on web login
    ip = ATTACKER_WEB[2]
    burst_start = start + timedelta(hours=3)
    for i in range(60):
        t = burst_start + timedelta(seconds=i * 2)
        events.append((t, f'{ip} - - [{nginx_ts(t)}] "POST /login HTTP/1.1" 401 120 "-" "python-requests/2.31"'))
    events.sort(key=lambda e: e[0])
    with open("logs/access.log", "w") as f:
        for _, line in events:
            f.write(line + "\n")
    print(f"access.log: {len(events)} rreshta")


if __name__ == "__main__":
    gen_auth()
    gen_nginx()
    print("Gati! Shiko dosjen logs/")