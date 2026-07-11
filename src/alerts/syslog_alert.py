"""
Syslog Alert Handler
"""

import logging
import socket
from typing import Dict, Any


class SyslogAlert:
    """Send alerts via syslog."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger("deception_grid.alerts.syslog")
        self.server = config.get("server", "localhost")
        self.port = config.get("port", 514)
        self.facility = config.get("facility", 16)  # local0
        self.protocol = config.get("protocol", "udp")
        self._socket = None
    
    def send(self, alert: Any) -> None:
        """Send alert via syslog."""
        try:
            message = self._format_syslog(alert)
            
            if self.protocol == "udp":
                self._send_udp(message)
            else:
                self._send_tcp(message)
            
            self.logger.info(f"Syslog alert sent: {alert.title}")
            
        except Exception as e:
            self.logger.error(f"Failed to send syslog: {e}")
    
    def _send_udp(self, message: str) -> None:
        """Send via UDP."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(message.encode(), (self.server, self.port))
        finally:
            sock.close()
    
    def _send_tcp(self, message: str) -> None:
        """Send via TCP."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self.server, self.port))
            sock.send(message.encode())
        finally:
            sock.close()
    
    def _format_syslog(self, alert: Any) -> str:
        """Format alert for syslog."""
        severity_map = {
            "critical": 2,  # Critical
            "high": 3,      # Error
            "medium": 4,    # Warning
            "low": 5,       # Notice
            "info": 6       # Informational
        }
        
        severity = severity_map.get(alert.severity, 6)
        priority = (self.facility * 8) + severity
        
        # syslog format: <priority>timestamp hostname app[pid]: message
        timestamp = alert.timestamp.strftime("%Y-%m-%dT%H:%M:%S")
        
        message = (
            f"<{priority}>{timestamp} deception-grid "
            f"[deception-grid]: "
            f"[{alert.severity.upper()}] {alert.title} - "
            f"{alert.description} "
            f"(source={alert.source}, id={alert.id})"
        )
        
        return message
    
    def close(self) -> None:
        """Close the syslog connection."""
        if self._socket:
            self._socket.close()
