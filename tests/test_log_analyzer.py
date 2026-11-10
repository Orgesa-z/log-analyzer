from datetime import datetime, timedelta

import detector
import parsers

T0 = datetime(2026, 11, 8, 10, 0, 0)


def ssh_event(i, ip="1.2.3.4", success=False):
    return {"time": T0 + timedelta(seconds=i), "ip": ip, "user": f"u{i % 3}",
            "success": success, "source": "ssh"}


def web_event(i, path="/", status=200, method="GET", agent="Mozilla/5.0", ip="5.6.7.8"):
    return {"time": T0 + timedelta(seconds=i), "ip": ip, "method": method,
            "path": path, "status": status, "agent": agent, "source": "nginx"}


def kinds(alerts):
    return {a["kind"] for a in alerts}


# ---------- Parsera ----------

def test_parse_ssh(tmp_path):
    f = tmp_path / "auth.log"
    f.write_text(
        "Nov 08 09:15:22 server sshd[1234]: Failed password for invalid user oracle from 45.155.205.233 port 4455 ssh2\n"
        "Nov  8 09:16:00 server sshd[1235]: Accepted password for root from 45.155.205.233 port 4456 ssh2\n"
        "rresht i çuditshëm që nuk është log\n",
        encoding="utf-8",
    )
    events = parsers.parse_ssh(str(f), year=2026)
    assert len(events) == 2
    assert events[0]["success"] is False
    assert events[0]["user"] == "oracle"
    assert events[0]["ip"] == "45.155.205.233"
    assert events[1]["success"] is True
    assert events[1]["user"] == "root"


def test_parse_nginx_with_spaces_in_path(tmp_path):
    f = tmp_path / "access.log"
    f.write_text(
        '91.240.118.172 - - [08/Nov/2026:09:15:22 +0000] "GET /search?q=\' OR \'1\'=\'1 HTTP/1.1" 400 300 "-" "sqlmap/1.7"\n'
        '192.168.1.10 - - [08/Nov/2026:09:15:23 +0000] "GET /index.html HTTP/1.1" 200 512 "-" "Mozilla/5.0"\n',
        encoding="utf-8",
    )
    events = parsers.parse_nginx(str(f))
    assert len(events) == 2
    assert events[0]["status"] == 400
    assert "OR" in events[0]["path"]
    assert events[0]["agent"] == "sqlmap/1.7"
    assert events[1]["path"] == "/index.html"


# ---------- Detektori SSH ----------

def test_ssh_bruteforce_detected():
    alerts = []
    events = [ssh_event(i) for i in range(12)]
    detector.detect_ssh_bruteforce(events, alerts)
    assert "SSH brute-force" in kinds(alerts)


def test_ssh_few_failures_no_alert():
    alerts = []
    events = [ssh_event(i) for i in range(3)]
    detector.detect_ssh_bruteforce(events, alerts)
    assert alerts == []


def test_ssh_failures_spread_over_time_no_alert():
    alerts = []
    events = [ssh_event(i * 120) for i in range(12)]  # 1 dështim çdo 2 minuta
    detector.detect_ssh_bruteforce(events, alerts)
    assert alerts == []


def test_ssh_successful_login_after_bruteforce_is_critical():
    alerts = []
    events = [ssh_event(i) for i in range(12)] + [ssh_event(60, success=True)]
    detector.detect_ssh_bruteforce(events, alerts)
    assert "Brute-force i SUKSESSHËM" in kinds(alerts)
    assert any(a["severity"] == "CRITICAL" for a in alerts)


# ---------- Detektori web ----------

def test_web_scan_detected():
    alerts = []
    events = [web_event(i, path="/wp-login.php", status=404) for i in range(20)]
    detector.detect_web(events, alerts)
    assert "Skanim web" in kinds(alerts)


def test_web_injection_detected():
    alerts = []
    events = [web_event(0, path="/search?q=' OR '1'='1", status=500)]
    detector.detect_web(events, alerts)
    assert "Injection (SQLi/XSS)" in kinds(alerts)


def test_web_login_bruteforce_detected():
    alerts = []
    events = [web_event(i, path="/login", status=401, method="POST") for i in range(20)]
    detector.detect_web(events, alerts)
    assert "Brute-force web login" in kinds(alerts)


def test_web_bad_user_agent_detected():
    alerts = []
    events = [web_event(0, agent="sqlmap/1.7")]
    detector.detect_web(events, alerts)
    assert "User-agent i dyshimtë" in kinds(alerts)


def test_web_normal_traffic_no_alert():
    alerts = []
    events = [web_event(i, path="/index.html") for i in range(10)]
    detector.detect_web(events, alerts)
    assert alerts == []




def test_parse_ssh_modern_iso_format(tmp_path):
    f = tmp_path / "auth.log"
    f.write_text(
        "2026-11-10T06:44:15.170038+01:00 host sshd-session[1819]: Invalid user fakeuser14 from 127.0.0.1 port 40118\n",
        encoding="utf-8",
    )
    events = parsers.parse_ssh(str(f))
    assert len(events) == 1
    assert events[0]["user"] == "fakeuser14"
    assert events[0]["ip"] == "127.0.0.1"


def test_parse_nginx_ipv6(tmp_path):
    f = tmp_path / "access.log"
    f.write_text(
        '::1 - - [10/Nov/2026:06:44:31 +0100] "GET /.env HTTP/1.1" 404 162 "-" "curl/8.18.0"\n',
        encoding="utf-8",
    )
    events = parsers.parse_nginx(str(f))
    assert len(events) == 1
    assert events[0]["ip"] == "::1"