"""
Webhook Alert Handler
"""

import logging
import json
import requests
from typing import Dict, Any


class WebhookAlert:
    """Send alerts via webhook (Slack, Discord, etc.)."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger("deception_grid.alerts.webhook")
        self.url = config.get("url", "")
        self.headers = config.get("headers", {"Content-Type": "application/json"})
        self.format = config.get("format", "slack")
    
    def send(self, alert: Any) -> None:
        """Send alert via webhook."""
        if not self.url:
            self.logger.warning("No webhook URL configured, skipping")
            return
        
        try:
            if self.format == "slack":
                payload = self._format_slack(alert)
            elif self.format == "discord":
                payload = self._format_discord(alert)
            else:
                payload = self._format_generic(alert)
            
            response = requests.post(
                self.url,
                json=payload,
                headers=self.headers,
                timeout=10
            )
            
            if response.status_code == 200:
                self.logger.info(f"Webhook alert sent: {alert.title}")
            else:
                self.logger.warning(f"Webhook returned status {response.status_code}")
                
        except Exception as e:
            self.logger.error(f"Failed to send webhook: {e}")
    
    def _format_slack(self, alert: Any) -> Dict[str, Any]:
        """Format alert for Slack."""
        severity_emoji = {
            "critical": ":rotating_light:",
            "high": ":warning:",
            "medium": ":exclamation:",
            "low": ":information_source:",
            "info": ":bulb:"
        }
        
        emoji = severity_emoji.get(alert.severity, ":grey_question:")
        
        return {
            "attachments": [{
                "color": self._get_severity_color(alert.severity),
                "title": f"{emoji} {alert.title}",
                "text": alert.description,
                "fields": [
                    {"title": "Severity", "value": alert.severity.upper(), "short": True},
                    {"title": "Source", "value": alert.source, "short": True},
                    {"title": "Time", "value": alert.timestamp.isoformat(), "short": True},
                    {"title": "Alert ID", "value": alert.id, "short": True}
                ],
                "footer": "Deception Grid",
                "ts": int(alert.timestamp.timestamp())
            }]
        }
    
    def _format_discord(self, alert: Any) -> Dict[str, Any]:
        """Format alert for Discord."""
        return {
            "embeds": [{
                "title": alert.title,
                "description": alert.description,
                "color": int(self._get_severity_color(alert.severity).replace('#', ''), 16),
                "fields": [
                    {"name": "Severity", "value": alert.severity.upper(), "inline": True},
                    {"name": "Source", "value": alert.source, "inline": True},
                    {"name": "Time", "value": alert.timestamp.isoformat(), "inline": False}
                ],
                "footer": {"text": f"Alert ID: {alert.id}"}
            }]
        }
    
    def _format_generic(self, alert: Any) -> Dict[str, Any]:
        """Format alert as generic JSON."""
        return {
            "alert": alert.to_dict()
        }
    
    def _get_severity_color(self, severity: str) -> str:
        """Get color for severity level."""
        colors = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#28a745",
            "info": "#17a2b8"
        }
        return colors.get(severity, "#6c757d")
