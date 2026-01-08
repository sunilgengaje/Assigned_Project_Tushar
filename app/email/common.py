
import os
import smtplib
from email.message import EmailMessage
from dotenv import load_dotenv
load_dotenv()

def send_password_email(to_email, password, username=None):
    smtp_host = os.getenv('SMTP_HOST')
    smtp_port = int(os.getenv('SMTP_PORT'))
    smtp_user = os.getenv('SMTP_USER')
    smtp_pass = os.getenv('SMTP_PASS')
    from_email = os.getenv('FROM_EMAIL', smtp_user)
    subject = 'Your Aggregator Account Password'
    user_info = f"Username: {username}\n" if username else ""
    body = f"""
    Dear User,\n\nYour aggregator account has been created.\n\n Username: {to_email}\nTemporary password: {password}\n\nPlease log in and change your password after first login.\n\nRegards,\nSupport Team
    """
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = from_email
    msg['To'] = to_email
    msg.set_content(body)
    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
        return {"success": True}
    except smtplib.SMTPAuthenticationError as e:
        return {"success": False, "error_code": "SMTP_AUTH_ERROR", "message": "SMTP authentication failed", "details": str(e)}
    except smtplib.SMTPConnectError as e:
        return {"success": False, "error_code": "SMTP_CONNECT_ERROR", "message": "SMTP connection failed", "details": str(e)}
    except smtplib.SMTPRecipientsRefused as e:
        return {"success": False, "error_code": "SMTP_RECIPIENTS_REFUSED", "message": "Recipient address refused", "details": str(e)}
    except smtplib.SMTPException as e:
        return {"success": False, "error_code": "SMTP_ERROR", "message": "SMTP error occurred", "details": str(e)}
    except Exception as e:
        return {"success": False, "error_code": "EMAIL_SEND_ERROR", "message": "Failed to send email", "details": str(e)}
