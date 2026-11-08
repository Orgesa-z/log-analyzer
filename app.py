import sqlite3
from collections import Counter

import pycountry
from flask import Flask, jsonify, render_template

import detector
import reputation

app = Flask(__name__)


def get_alerts():
    con = sqlite3.connect("alerts.db")
    con.row_factory = sqlite3.Row
    rows = con.execute("SELECT * FROM alerts ORDER BY id").fetchall()
    con.close()
    return [dict(r) for r in rows]


def iso3(code):
    try:
        return pycountry.countries.get(alpha_2=code).alpha_3
    except Exception:
        return None


@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/data")
def data():
    alerts = get_alerts()
    for a in alerts:
        a["abuse"] = reputation.check(a["ip"])
    sev = Counter(a["severity"] for a in alerts)
    top_ips = Counter(a["ip"] for a in alerts).most_common(8)
    kinds = Counter(a["kind"] for a in alerts)
    timeline = Counter(a["time"][:13] + ":00" for a in alerts)

    countries = Counter()
    for a in alerts:
        ab = a.get("abuse")
        if ab and ab.get("country"):
            code = iso3(ab["country"])
            if code:
                countries[code] += 1

    return jsonify({
        "alerts": alerts,
        "severity": dict(sev),
        "top_ips": top_ips,
        "kinds": dict(kinds),
        "timeline": sorted(timeline.items()),
        "countries": list(countries.items()),
    })


@app.route("/api/rescan", methods=["POST"])
def rescan():
    alerts = detector.run()
    return jsonify({"count": len(alerts)})


if __name__ == "__main__":
    detector.run()
    app.run(debug=True)