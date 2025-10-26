"""
SMTP Email Sender for the College Management System
"""
import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging

logger = logging.getLogger(__name__)

class SMTPEmailSender:
    def __init__(self):
        """Initialize SMTP email sender"""
        self.smtp_host = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
        self.smtp_port = int(os.environ.get('SMTP_PORT', '587'))
        self.smtp_username = os.environ.get('SMTP_USERNAME')
        self.smtp_password = os.environ.get('SMTP_PASSWORD')
        
        if not all([self.smtp_username, self.smtp_password]):
            logger.warning("SMTP credentials not configured")
    
    def send_email(self, recipient: str, subject: str, message: str) -> bool:
        """Send email using SMTP"""
        try:
            if not all([self.smtp_username, self.smtp_password]):
                logger.error("SMTP credentials not configured")
                return False
            
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.smtp_username
            msg['To'] = recipient
            msg['Subject'] = subject
            
            # Add message body
            msg.attach(MIMEText(message, 'plain'))
            
            # Connect to SMTP server
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_username, self.smtp_password)
                server.send_message(msg)
            
            logger.info(f"Email sent successfully to {recipient}")
            return True
            
        except Exception as e:
            logger.error(f"Error sending email: {str(e)}")
            return False

# Global instance
_smtp_sender = None

def get_smtp_sender():
    """Get global SMTP sender instance"""
    global _smtp_sender
    if _smtp_sender is None:
        _smtp_sender = SMTPEmailSender()
    return _smtp_sender

def send_smtp_email(recipient: str, subject: str, message: str) -> bool:
    """Send email using global SMTP sender instance"""
    return get_smtp_sender().send_email(recipient, subject, message)