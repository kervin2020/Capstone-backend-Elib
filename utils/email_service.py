import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from os import getenv
from typing import List

SMTP_SERVER = getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(getenv("SMTP_PORT", "587"))
SMTP_USERNAME = getenv("SMTP_USERNAME")  # ton adresse mail
SMTP_PASSWORD = getenv("SMTP_PASSWORD")  # mot de passe


def send_email(destinataires: List[str], sujet: str, corps_text: str, corps_html: str = None):
    """
    Envoie un mail simple (texte + html optionnel) via SMTP.
    """
    if not SMTP_USERNAME or not SMTP_PASSWORD:
        raise RuntimeError(
            "Variables SMTP_USERNAME et/ou SMTP_PASSWORD non définies.")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = sujet
    msg["From"] = SMTP_USERNAME
    msg["To"] = ", ".join(destinataires)

    msg.attach(MIMEText(corps_text, "plain", "utf-8"))
    if corps_html:
        msg.attach(MIMEText(corps_html, "html", "utf-8"))

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.sendmail(SMTP_USERNAME, destinataires, msg.as_string())


# facilite metier
def notify_loan_deadline(user_email: str, ebook_title: str, days_left: int):
    """
    Envoie un rappel de retour pour un prêt.
    """
    objet = f"Rappel : retour du livre '{ebook_title}' dans {days_left} jours"
    corps = (f"Bonjour,\n\n"
             f"Le délai de votre prêt pour le livre '{ebook_title}' expire dans {days_left} jour(s).\n"
             f"Pensez à le rendre à temps pour éviter des pénalités.\n\n"
             f"Cordialement,\nL'équipe E-Lib")

    send_email([user_email], objet, corps)
