"""
Database Honeypot Module (MySQL/PostgreSQL)
"""

import socket
import threading
import logging
import struct
from typing import Dict, Any, Optional
from datetime import datetime


class DatabaseHoneypot:
    """Simulates a database server to capture attacker queries."""
    
    def __init__(self, config: Dict[str, Any], engine: Any = None):
        self.config = config
        self.engine = engine
        self.logger = logging.getLogger("deception_grid.database")
        self.port = config.get("port", 3306)
        self.db_type = config.get("type", "mysql")
        self.server = None
        self._running = False
        self._connections = {}
        self.fake_databases = config.get("fake_databases", ["users", "credentials"])
    
    def start(self) -> None:
        """Start the database honeypot server."""
        self._running = True
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("0.0.0.0", self.port))
        self.server.listen(100)
        self.server.settimeout(1.0)
        
        self.logger.info(f"Database Honeypot ({self.db_type}) listening on port {self.port}")
        
        thread = threading.Thread(target=self._accept_loop, daemon=True)
        thread.start()
    
    def stop(self) -> None:
        """Stop the database honeypot server."""
        self._running = False
        if self.server:
            self.server.close()
        self.logger.info("Database Honeypot stopped")
    
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
        """Handle a database client connection."""
        conn_id = f"{addr[0]}:{addr[1]}"
        self._connections[conn_id] = {
            "start_time": datetime.utcnow(),
            "queries": [],
            "authenticated": False
        }
        
        try:
            if self.db_type == "mysql":
                self._handle_mysql(client, addr, conn_id)
            else:
                self._handle_postgresql(client, addr, conn_id)
                
        except Exception as e:
            self.logger.debug(f"Client error: {e}")
        finally:
            del self._connections[conn_id]
            client.close()
    
    def _handle_mysql(self, client: socket.socket, addr: tuple, conn_id: str) -> None:
        """Handle MySQL protocol."""
        # Send greeting packet
        greeting = self._create_mysql_greeting()
        client.send(greeting)
        
        # Receive authentication
        data = client.recv(4096)
        if data:
            # Parse username (simplified)
            try:
                # Skip header (4 bytes) + packet type (1 byte) + client capabilities (4 bytes)
                # + max packet size (4 bytes) + charset (1 byte) + reserved (23 bytes)
                offset = 36
                username_end = data.index(b'\x00', offset)
                username = data[offset:username_end].decode('utf-8', errors='ignore')
                
                self._connections[conn_id]["username"] = username
                
                self._emit_event("auth_attempt", {
                    "src_ip": addr[0],
                    "src_port": addr[1],
                    "username": username,
                    "auth_data": data[username_end+1:username_end+33].hex()
                })
            except:
                pass
            
            # Send auth error
            error_packet = self._create_mysql_error(1045, "Access denied")
            client.send(error_packet)
    
    def _handle_postgresql(self, client: socket.socket, addr: tuple, conn_id: str) -> None:
        """Handle PostgreSQL protocol."""
        # Receive startup message
        data = client.recv(4096)
        if data:
            # Parse startup message
            length = struct.unpack('!I', data[:4])[0]
            version = struct.unpack('!I', data[4:8])[0]
            
            self._emit_event("connection", {
                "src_ip": addr[0],
                "src_port": addr[1],
                "protocol_version": version,
                "data_preview": data[:100].hex()
            })
            
            # Send authentication request
            auth_request = struct.pack('!II', 8, 3)  # Auth request, cleartext
            client.send(auth_request)
            
            # Receive password
            password_data = client.recv(4096)
            if password_data:
                # Send auth failure
                error_msg = b"FATAL\0password authentication failed\0\x00"
                error_packet = struct.pack('!II', len(error_msg) + 8, 68) + error_msg
                client.send(error_packet)
    
    def _create_mysql_greeting(self) -> bytes:
        """Create a MySQL server greeting packet."""
        # Simplified greeting
        greeting = (
            b"\x00"  # Packet number
            b"\x00\x00\x00"  # Packet length (placeholder)
            b"\x0a"  # Protocol version 10
            b"8.0.32\x00"  # Server version
            b"\x01\x00\x00\x00"  # Connection ID
            b"\x00" + b"\x08" + b"\xff\xff" + b"\x00" +  # Auth plugin data
            b"\x01" +  # Capability flags
            b"\x00" * 10 +  # Reserved
            b"\x00" * 10 +  # Auth plugin data 2
            b"caching_sha2_password\x00"  # Auth plugin name
        )
        # Fix length
        length = len(greeting) - 4
        greeting = greeting[:1] + length.to_bytes(3, 'little') + greeting[4:]
        return greeting
    
    def _create_mysql_error(self, error_code: int, message: str) -> bytes:
        """Create a MySQL error packet."""
        msg_bytes = message.encode('utf-8')
        packet = struct.pack('<I', error_code) + b'#' + msg_bytes
        length = len(packet)
        return struct.pack('<I', length) + b'\x00\x01\x00' + packet
    
    def _emit_event(self, event_type: str, data: Dict[str, Any]) -> None:
        """Emit an event to the engine."""
        from ..deception_grid.engine import Event
        event = Event(f"database_honeypot_{self.db_type}", event_type, data)
        if self.engine:
            self.engine.emit_event(event)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get honeypot statistics."""
        return {
            "port": self.port,
            "type": self.db_type,
            "running": self._running,
            "active_connections": len(self._connections)
        }
