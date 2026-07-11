"""
SMB Honeypot Module
"""

import socket
import threading
import logging
import struct
from typing import Dict, Any
from datetime import datetime


class SMBHoneypot:
    """Simulates an SMB server to capture attacker behavior."""
    
    def __init__(self, config: Dict[str, Any], engine: Any = None):
        self.config = config
        self.engine = engine
        self.logger = logging.getLogger("deception_grid.smb")
        self.port = config.get("port", 445)
        self.share_name = config.get("share_name", "Public")
        self.server = None
        self._running = False
        self._connections = {}
    
    def start(self) -> None:
        """Start the SMB honeypot server."""
        self._running = True
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("0.0.0.0", self.port))
        self.server.listen(100)
        self.server.settimeout(1.0)
        
        self.logger.info(f"SMB Honeypot listening on port {self.port}")
        
        thread = threading.Thread(target=self._accept_loop, daemon=True)
        thread.start()
    
    def stop(self) -> None:
        """Stop the SMB honeypot server."""
        self._running = False
        if self.server:
            self.server.close()
        self.logger.info("SMB Honeypot stopped")
    
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
        """Handle an SMB client connection."""
        conn_id = f"{addr[0]}:{addr[1]}"
        self._connections[conn_id] = {
            "start_time": datetime.utcnow(),
            "commands": [],
            "authenticated": False
        }
        
        try:
            # SMB negotiation
            data = client.recv(4096)
            if data:
                self._capture_smb_command(addr, "NEGOTIATE", data)
                
                # Send negotiation response
                response = self._create_negotiate_response()
                client.send(response)
                
                # Session setup
                data = client.recv(4096)
                if data:
                    self._capture_smb_command(addr, "SESSION_SETUP", data)
                    
                    # Send session setup response (access denied)
                    response = self._create_session_response()
                    client.send(response)
                    
        except Exception as e:
            self.logger.debug(f"Client error: {e}")
        finally:
            del self._connections[conn_id]
            client.close()
    
    def _capture_smb_command(self, addr: tuple, command: str, data: bytes) -> None:
        """Capture SMB command for analysis."""
        self._emit_event("smb_command", {
            "src_ip": addr[0],
            "src_port": addr[1],
            "command": command,
            "data_size": len(data),
            "data_preview": data[:200].hex()
        })
    
    def _create_negotiate_response(self) -> bytes:
        """Create SMB negotiate response."""
        # Simplified SMB2 negotiate response
        header = (
            b'\xfe\x53\x4d\x42'  # Protocol magic
            b'\x40\x00\x00\x00'  # Header length
            b'\x00\x00\x00\x00'  # Status: Success
            b'\x00\x00'          # Command: Negotiate
            b'\x00\x00'          # Credits
            b'\x00\x00\x00\x00\x00\x00\x00\x00'  # Flags + NextCommand
            b'\x00\x00\x00\x00\x00\x00\x00\x00'  # MessageId
            b'\x00\x00\x00\x00\x00\x00\x00\x00'  # Reserved + TreeId
            b'\x00\x00\x00\x00\x00\x00\x00\x00'  # SessionId
            b'\x00\x00\x00\x00\x00\x00\x00\x00'  # Signature
        )
        return header
    
    def _create_session_response(self) -> bytes:
        """Create SMB session setup response (access denied)."""
        header = (
            b'\xfe\x53\x4d\x42'  # Protocol magic
            b'\x09\x00\x00\x00'  # Header length
            b'\x22\x00\x00\xc0'  # Status: Access Denied
            b'\x01\x00'          # Command: Session Setup
            b'\x00\x00'          # Credits
        )
        return header
    
    def _emit_event(self, event_type: str, data: Dict[str, Any]) -> None:
        """Emit an event to the engine."""
        from ..deception_grid.engine import Event
        event = Event("smb_honeypot", event_type, data)
        if self.engine:
            self.engine.emit_event(event)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get honeypot statistics."""
        return {
            "port": self.port,
            "share_name": self.share_name,
            "running": self._running,
            "active_connections": len(self._connections)
        }
