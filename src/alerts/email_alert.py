"""
Email Alert Handler
"""

import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any


class EmailAlert:
    """Send alerts via email."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger("deception_grid.alerts.email")
        self.smtp_server = config.get("smtp_server", "smtp.gmail.com")
        self.smtp_port = config.get("smtp_port", 587)
        self.username = config.get("username", "")
        self.password = config.get("password", "")
        self.recipients = config.get("recipients", [])
        self.from_address = config.get("from_address", self.username)
    
    def send(self, alert: Any) -> None:
        """Send alert via email."""
        if not self.recipients:
            self.logger.warning("No recipients configured, skipping email")
            return
        
        try:
            msg = MIMEMultipart()
            msg['From'] = self.from_address
            msg['To'] = ', '.join(self.recipients)
            msg['Subject'] = f"[{alert.severity.upper()}] {alert.title}"
            
            body = self._format_email_body(alert)
            msg.attach(MIMEText(body, 'html'))
            
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                if self.username and self.password:
                    server.login(self.username, self.password)
                server.send_message(msg)
            
            self.logger.info(f"Email alert sent: {alert.title}")
            
        except Exception as e:
            self.logger.error(f"Failed to send email: {e}")
    
    def _format_email_body(self, alert: Any) -> str:
        """Format alert as HTML email body."""
        severity_colors = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#28a745",
            "info": "#17a2b8"
        }
        
        color = severity_colors.get(alert.severity, "#6c757d")
        
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .alert-box {{ border-left: 4px solid {color}; padding: 15px; margin: 20px 0; background: #f8f9fa; }}
                .severity {{ color: {color}; font-weight: bold; text-transform: uppercase; }}
                table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <h2>Security Alert</h2>
            <div class="alert-box">
                <p><strong>Severity:</strong> <span class="severity">{alert.severity}</span></p>
                <p><strong>Title:</strong> {alert.title}</p>
                <p><strong>Description:</strong> {alert.description}</p>
                <p><strong>Source:</strong> {alert.source}</p>
                <p><strong>Time:</strong> {alert.timestamp}</p>
            </div>
            
            <h3>Details</h3>
            <table>
                <tr><th>Field</th><th>Value</th></tr>
                <tr><td>Alert ID</td><td>{alert.id}</td></tr>
                <tr><td>Source IP</td><td>{alert.data.get('data', {}).get('src_ip', 'N/A')}</td></tr>
                <tr><td>Event Type</td><td>{alert.data.get('event_type', 'N/A')}</td></tr>
            </table>
        </body>
        </html>
        """
