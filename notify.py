import os
import smtplib
from email.message import EmailMessage


def send_email(subject, body):
    """Dërgon email nëse GMAIL_USER dhe GMAIL_APP_PASSWORD janë vendosur. Kthen True/False."""
    user = os.environ.get("GMAIL_USER")
    password = os.environ.get("GMAIL_APP_PASSWORD")
    if not user or not password:
        return False

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = user
    msg["To"] = user
    msg.set_content(body)

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=15) as s:
            s.login(user, password)
            s.send_message(msg)
        return True
    except Exception as e:
        print("Email dështoi:", e)
        return False


if __name__ == "__main__":
    ok = send_email("[TEST] Log Analyzer", "Nëse e sheh këtë, njoftimet me email punojnë.")
    print("U dërgua" if ok else "Nuk u dërgua")