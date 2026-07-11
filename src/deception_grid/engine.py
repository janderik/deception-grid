"""
Core Engine - Event routing and management
"""

import logging
import threading
from typing import Dict, List, Optional, Any
from datetime import datetime
import yaml


class Event:
    """Represents a honeypot event."""
    
    def __init__(self, source: str, event_type: str, data: Dict[str, Any]):
        self.timestamp = datetime.utcnow()
        self.source = source
        self.event_type = event_type
        self.data = data
        self.id = f"{source}-{event_type}-{self.timestamp.timestamp()}"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "event_type": self.event_type,
            "data": self.data
        }


class DeceptionEngine:
    """Core engine that routes events between components."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger("deception_grid.engine")
        self.honeypots = {}
        self.capture = None
        self.alerts = None
        self.dashboard = None
        self._running = False
        self._lock = threading.Lock()
        self._event_queue = []
    
    def register_honeypot(self, name: str, honeypot: Any) -> None:
        """Register a honeypot module."""
        with self._lock:
            self.honeypots[name] = honeypot
            self.logger.info(f"Registered honeypot: {name}")
    
    def set_capture(self, capture: Any) -> None:
        """Set the TTP capture module."""
        self.capture = capture
        self.logger.info("TTP capture module registered")
    
    def set_alerts(self, alerts: Any) -> None:
        """Set the alert system."""
        self.alerts = alerts
        self.logger.info("Alert system registered")
    
    def set_dashboard(self, dashboard: Any) -> None:
        """Set the dashboard module."""
        self.dashboard = dashboard
        self.logger.info("Dashboard registered")
    
    def emit_event(self, event: Event) -> None:
        """Emit an event to the system."""
        self.logger.debug(f"Event received: {event.event_type} from {event.source}")
        
        # Store event
        with self._lock:
            self._event_queue.append(event)
            if len(self._event_queue) > 10000:
                self._event_queue = self._event_queue[-5000:]
        
        # Send to capture
        if self.capture:
            try:
                self.capture.process_event(event)
            except Exception as e:
                self.logger.error(f"Capture error: {e}")
        
        # Send to alerts
        if self.alerts:
            try:
                self.alerts.process_event(event)
            except Exception as e:
                self.logger.error(f"Alert error: {e}")
        
        # Send to dashboard
        if self.dashboard:
            try:
                self.dashboard.process_event(event)
            except Exception as e:
                self.logger.error(f"Dashboard error: {e}")
    
    def start(self) -> None:
        """Start all honeypots."""
        self.logger.info("Starting Deception Grid...")
        self._running = True
        
        for name, honeypot in self.honeypots.items():
            try:
                honeypot.start()
                self.logger.info(f"Started honeypot: {name}")
            except Exception as e:
                self.logger.error(f"Failed to start {name}: {e}")
    
    def stop(self) -> None:
        """Stop all honeypots."""
        self.logger.info("Stopping Deception Grid...")
        self._running = False
        
        for name, honeypot in self.honeypots.items():
            try:
                honeypot.stop()
                self.logger.info(f"Stopped honeypot: {name}")
            except Exception as e:
                self.logger.error(f"Failed to stop {name}: {e}")
    
    def get_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent events."""
        with self._lock:
            return [e.to_dict() for e in self._event_queue[-limit:]]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get engine statistics."""
        with self._lock:
            event_count = len(self._event_queue)
            event_types = {}
            for e in self._event_queue:
                event_types[e.event_type] = event_types.get(e.event_type, 0) + 1
        
        return {
            "running": self._running,
            "total_events": event_count,
            "event_types": event_types,
            "active_honeypots": list(self.honeypots.keys())
        }


def load_config(config_path: str) -> Dict[str, Any]:
    """Load configuration from YAML file."""
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)


def create_default_config() -> Dict[str, Any]:
    """Create default configuration."""
    return {
        "engine": {
            "log_level": "INFO",
            "max_connections": 1000
        },
        "honeypots": {
            "ssh": {"enabled": True, "port": 2222},
            "http": {"enabled": True, "port": 8080},
            "database": {"enabled": True, "port": 3306},
            "smb": {"enabled": True, "port": 445}
        },
        "capture": {"enabled": True, "mitre_mapping": True},
        "alerts": {
            "email": {"enabled": False},
            "webhook": {"enabled": False},
            "syslog": {"enabled": True}
        },
        "dashboard": {"enabled": True, "port": 5000}
    }
