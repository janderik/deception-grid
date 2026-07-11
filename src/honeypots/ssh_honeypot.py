"""
SSH Honeypot Module
"""

import socket
import threading
import logging
from typing import Dict, Any, Optional
from datetime import datetime


class SSHHoneypot:
    """Simulates an SSH server to capture attacker behavior."""
    
    def __init__(self, config: Dict[str, Any], engine: Any = None):
        self.config = config
        self.engine = engine
        self.logger = logging.getLogger("deception_grid.ssh")
        self.port = config.get("port", 2222)
        self.banner = config.get("banner", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1")
        self.server = None
        self._running = False
        self._connections = {}
    
    def start(self) -> None:
        """Start the SSH honeypot server."""
        self._running = True
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("0.0.0.0", self.port))
        self.server.listen(100)
        self.server.settimeout(1.0)
        
        self.logger.info(f"SSH Honeypot listening on port {self.port}")
        
        thread = threading.Thread(target=self._accept_loop, daemon=True)
        thread.start()
    
    def stop(self) -> None:
        """Stop the SSH honeypot server."""
        self._running = False
        if self.server:
            self.server.close()
        self.logger.info("SSH Honeypot stopped")
    
    def _accept_loop(self) -> None:
        """Accept incoming connections."""
        while self._running:
            try:
                client, addr = self.server.accept()
                self.logger.info(f"Connection from {addr[0]}:{addr[1]}")
                thread = threading.Thread(
                    target=self._handle_client,
                    args=(client, addr),
                    daemon=True
                )
                thread.start()
            except socket.timeout:
                continue
            except Exception as e:
                if self._running:
                    self.logger.error(f"Accept error: {e}")
    
    def _handle_client(self, client: socket.socket, addr: tuple) -> None:
        """Handle an SSH client connection."""
        conn_id = f"{addr[0]}:{addr[1]}"
        self._connections[conn_id] = {
            "start_time": datetime.utcnow(),
            "commands": [],
            "authenticated": False,
            "username": None
        }
        
        try:
            # Send banner
            client.send(f"{self.banner}\r\n".encode())
            
            # Simulate SSH key exchange
            data = client.recv(4096)
            if data:
                self._emit_event("connection", {
                    "src_ip": addr[0],
                    "src_port": addr[1],
                    "banner_sent": self.banner,
                    "client_data": data[:100].hex() if len(data) > 100 else data.hex()
                })
            
            # Simulate authentication prompt
            client.send(b"Password: ")
            
            while self._running:
                data = client.recv(4096)
                if not data:
                    break
                
                password = data.decode('utf-8', errors='ignore').strip()
                self._connections[conn_id]["commands"].append(password)
                
                # Always reject with "Permission denied"
                client.send(b"Permission denied, please try again.\r\nPassword: ")
                
                self._emit_event("auth_attempt", {
                    "src_ip": addr[0],
                    "src_port": addr[1],
                    "password_length": len(password),
                    "password_hash": hash(password)
                })
                
        except Exception as e:
            self.logger.debug(f"Client error: {e}")
        finally:
            del self._connections[conn_id]
            client.close()
    
    def _emit_event(self, event_type: str, data: Dict[str, Any]) -> None:
        """Emit an event to the engine."""
        from ..deception_grid.engine import Event
        event = Event("ssh_honeypot", event_type, data)
        if self.engine:
            self.engine.emit_event(event)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get honeypot statistics."""
        return {
            "port": self.port,
            "running": self._running,
            "active_connections": len(self._connections)
        }
