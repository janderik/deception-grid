"""
HTTP Honeypot Module
"""

import http.server
import socketserver
import threading
import logging
from typing import Dict, Any, List
from datetime import datetime


class HoneypotHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler for honeypot."""
    
    honeypot_engine = None
    honeypot_config = {}
    fake_pages = {}
    
    def log_message(self, format, *args):
        """Override to use our logger."""
        logging.getLogger("deception_grid.http").info(
            f"{self.client_address[0]} - {format % args}"
        )
    
    def do_GET(self) -> None:
        """Handle GET requests."""
        self._capture_request("GET")
        self._send_fake_response()
    
    def do_POST(self) -> None:
        """Handle POST requests."""
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length else b""
        
        self._capture_request("POST", body)
        self._send_fake_response()
    
    def do_PUT(self) -> None:
        """Handle PUT requests."""
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length else b""
        
        self._capture_request("PUT", body)
        self._send_fake_response()
    
    def do_DELETE(self) -> None:
        """Handle DELETE requests."""
        self._capture_request("DELETE")
        self._send_fake_response()
    
    def _capture_request(self, method: str, body: bytes = None) -> None:
        """Capture request data for analysis."""
        from ..deception_grid.engine import Event
        
        data = {
            "src_ip": self.client_address[0],
            "method": method,
            "path": self.path,
            "headers": dict(self.headers),
            "timestamp": datetime.utcnow().isoformat()
        }
        
        if body:
            data["body_size"] = len(body)
            try:
                data["body_preview"] = body[:500].decode('utf-8', errors='ignore')
            except:
                data["body_preview"] = body[:500].hex()
        
        if self.honeypot_engine:
            event = Event("http_honeypot", "request", data)
            self.honeypot_engine.emit_event(event)
    
    def _send_fake_response(self) -> None:
        """Send a realistic-looking fake response."""
        # Check for known paths
        path = self.path.rstrip('/')
        
        if path in self.fake_pages:
            page = self.fake_pages[path]
            content = page.get("content", "<html><body>OK</body></html>")
            status = page.get("status", 200)
        else:
            # Default response
            status = 200
            content = self._generate_default_page()
        
        self.send_response(status)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Server', self.honeypot_config.get('server_header', 'nginx/1.18.0'))
        self.end_headers()
        self.wfile.write(content.encode())
    
    def _generate_default_page(self) -> str:
        """Generate a default fake page."""
        return """<!DOCTYPE html>
<html>
<head>
    <title>Welcome</title>
</head>
<body>
    <h1>Welcome to our website</h1>
    <p>This is a demo page.</p>
</body>
</html>"""


class HTTPHoneypot:
    """HTTP honeypot server."""
    
    def __init__(self, config: Dict[str, Any], engine: Any = None):
        self.config = config
        self.engine = engine
        self.logger = logging.getLogger("deception_grid.http")
        self.port = config.get("port", 8080)
        self.server = None
        self._running = False
        self._connections = {}
        
        # Set up fake pages
        self.fake_pages = {
            "/admin": {"content": self._login_page("Admin Panel"), "status": 200},
            "/login": {"content": self._login_page("Login"), "status": 200},
            "/api": {"content": '{"status": "ok", "version": "1.0.0"}', "status": 200},
            "/wp-admin": {"content": self._login_page("WordPress Admin"), "status": 200},
            "/phpmyadmin": {"content": self._login_page("phpMyAdmin"), "status": 200},
            "/.env": {"content": "DB_PASSWORD=secret123\nAPI_KEY=abc123", "status": 200},
        }
    
    def start(self) -> None:
        """Start the HTTP honeypot server."""
        self._running = True
        
        # Configure handler
        HoneypotHandler.honeypot_engine = self.engine
        HoneypotHandler.honeypot_config = self.config
        HoneypotHandler.fake_pages = self.fake_pages
        
        self.server = socketserver.TCPServer(("0.0.0.0", self.port), HoneypotHandler)
        self.logger.info(f"HTTP Honeypot listening on port {self.port}")
        
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
    
    def stop(self) -> None:
        """Stop the HTTP honeypot server."""
        self._running = False
        if self.server:
            self.server.shutdown()
        self.logger.info("HTTP Honeypot stopped")
    
    def add_fake_page(self, path: str, content: str, status: int = 200) -> None:
        """Add a custom fake page."""
        self.fake_pages[path] = {"content": content, "status": status}
    
    def _login_page(self, title: str) -> str:
        """Generate a fake login page."""
        return f"""<!DOCTYPE html>
<html>
<head>
    <title>{title}</title>
    <style>
        body {{ font-family: Arial, sans-serif; background: #f5f5f5; }}
        .login-box {{ max-width: 300px; margin: 100px auto; padding: 20px;
                      background: white; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        input {{ width: 100%; padding: 10px; margin: 5px 0; box-sizing: border-box; }}
        button {{ width: 100%; padding: 10px; background: #007bff; color: white;
                  border: none; border-radius: 3px; cursor: pointer; }}
    </style>
</head>
<body>
    <div class="login-box">
        <h2>{title}</h2>
        <form method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>"""
    
    def get_stats(self) -> Dict[str, Any]:
        """Get honeypot statistics."""
        return {
            "port": self.port,
            "running": self._running,
            "fake_pages": list(self.fake_pages.keys())
        }
