import os
import requests

r = requests.get(
    "https://api.abuseipdb.com/api/v2/blacklist",
    headers={"Key": os.environ["ABUSEIPDB_KEY"], "Accept": "text/plain"},
    params={"confidenceMinimum": 100, "limit": 6},
    timeout=10,
)
r.raise_for_status()
ips = r.text.split()
open("bad_ips.txt", "w").write("\n".join(ips))
print("U ruajtën:", ips)