# Log Analyzer: Zbulim sulmesh

Mjet në Python që lexon log-e të serverit (SSH auth.log dhe nginx access.log), zbulon brute-force, skanime dhe IP të dyshimta, dhe i shfaq alarmet në një dashboard web.

## Çfarë zbulon

- SSH brute-force dhe hyrje të suksesshme pas sulmit (CRITICAL)
- Injection: SQLi, XSS, path traversal (HIGH)
- Brute-force në login web (HIGH)
- Skanim web për path të dyshimta (MEDIUM)
- User-agent të dyshimtë: sqlmap, Nikto, curl (LOW)

## Instalimi

```powershell
git clone https://github.com/Orgesa-z/log-analyzer.git
cd log-analyzer
python -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements.txt
mkdir logs
python generate_logs.py
python app.py
```

Pastaj hap http://127.0.0.1:5000

## Skedarët

- parsers.py: parsera me regex për log-et
- detector.py: rregullat e detektimit dhe ruajtja në SQLite
- app.py: server Flask me API
- templates/dashboard.html: dashboard-i
- generate_logs.py: gjenerator i log-eve të rreme për testim
