"""
Alert Manager - Central alert processing
"""

import logging
import threading
from typing import Dict, Any, List, Optional
from datetime import datetime
from collections import defaultdict


class Alert:
    """Represents a security alert."""
    
    def __init__(self, severity: str, title: str, description: str, source: str, data: Dict[str, Any] = None):
        self.timestamp = datetime.utcnow()
        self.severity = severity
        self.title = title
        self.description = description
        self.source = source
        self.data = data or {}
        self.id = f"alert-{self.timestamp.timestamp()}"
        self.acknowledged = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "source": self.source,
            "data": self.data,
            "acknowledged": self.acknowledged
        }


class AlertManager:
    """Manages and routes security alerts."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger("deception_grid.alerts")
        self.alerts: List[Alert] = []
        self.handlers = []
        self._lock = threading.Lock()
        self._rules = self._load_rules()
    
    def _load_rules(self) -> List[Dict[str, Any]]:
        """Load alert rules."""
        return [
            {
                "name": "brute_force",
                "condition": lambda e: e.get("event_type") == "auth_attempt",
                "severity": "high",
                "title": "Brute Force Attempt Detected",
                "threshold": 5,
                "window": 300
            },
            {
                "name": "suspicious_path",
                "condition": lambda e: any(p in e.get("data", {}).get("path", "") 
                                          for p in ["/admin", "/wp-admin", "/phpmyadmin", "/.env"]),
                "severity": "medium",
                "title": "Suspicious Path Accessed"
            },
            {
                "name": "sensitive_file",
                "condition": lambda e: any(f in e.get("data", {}).get("path", "") 
                                          for f in ["/etc/passwd", "/etc/shadow", ".ssh/"]),
                "severity": "critical",
                "title": "Sensitive File Access Attempt"
            }
        ]
    
    def register_handler(self, handler: Any) -> None:
        """Register an alert handler."""
        self.handlers.append(handler)
        self.logger.info(f"Registered alert handler: {handler.__class__.__name__}")
    
    def process_event(self, event: Any) -> None:
        """Process an event and generate alerts if needed."""
        event_dict = event.to_dict() if hasattr(event, 'to_dict') else event
        
        for rule in self._rules:
            try:
                if rule["condition"](event_dict):
                    alert = Alert(
                        severity=rule["severity"],
                        title=rule["title"],
                        description=f"Detected: {rule['name']} from {event_dict.get('data', {}).get('src_ip', 'unknown')}",
                        source=event_dict.get("source", "unknown"),
                        data=event_dict
                    )
                    self._send_alert(alert)
            except Exception as e:
                self.logger.error(f"Error processing rule {rule['name']}: {e}")
    
    def _send_alert(self, alert: Alert) -> None:
        """Send alert to all handlers."""
        with self._lock:
            self.alerts.append(alert)
            
            # Keep only last 1000 alerts
            if len(self.alerts) > 1000:
                self.alerts = self.alerts[-1000:]
        
        self.logger.warning(f"ALERT [{alert.severity.upper()}]: {alert.title}")
        
        for handler in self.handlers:
            try:
                handler.send(alert)
            except Exception as e:
                self.logger.error(f"Handler error: {e}")
    
    def get_alerts(self, severity: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Get alerts, optionally filtered by severity."""
        with self._lock:
            alerts = self.alerts.copy()
        
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        
        return [a.to_dict() for a in alerts[-limit:]]
    
    def acknowledge_alert(self, alert_id: str) -> bool:
        """Acknowledge an alert."""
        with self._lock:
            for alert in self.alerts:
                if alert.id == alert_id:
                    alert.acknowledged = True
                    return True
        return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get alert statistics."""
        with self._lock:
            severity_counts = defaultdict(int)
            for alert in self.alerts:
                severity_counts[alert.severity] += 1
        
        return {
            "total_alerts": len(self.alerts),
            "by_severity": dict(severity_counts),
            "unacknowledged": sum(1 for a in self.alerts if not a.acknowledged)
        }
