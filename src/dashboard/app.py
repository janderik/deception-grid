"""
Flask Dashboard Application
"""

from flask import Flask, render_template, jsonify, request
import logging
from typing import Dict, Any, Optional


def create_app(config: Dict[str, Any] = None, engine: Any = None) -> Flask:
    """Create Flask dashboard application."""
    app = Flask(__name__)
    
    if config:
        app.config.update(config)
    
    engine_ref = {"engine": engine}
    
    @app.route('/')
    def index():
        """Dashboard home page."""
        return render_template('index.html')
    
    @app.route('/api/stats')
    def get_stats():
        """Get engine statistics."""
        if engine_ref["engine"]:
            stats = engine_ref["engine"].get_stats()
            return jsonify(stats)
        return jsonify({"error": "Engine not initialized"})
    
    @app.route('/api/events')
    def get_events():
        """Get recent events."""
        limit = request.args.get('limit', 100, type=int)
        if engine_ref["engine"]:
            events = engine_ref["engine"].get_events(limit)
            return jsonify(events)
        return jsonify([])
    
    @app.route('/api/honeypots')
    def get_honeypots():
        """Get honeypot status."""
        if engine_ref["engine"]:
            honeypots = {}
            for name, hp in engine_ref["engine"].honeypots.items():
                honeypots[name] = hp.get_stats()
            return jsonify(honeypots)
        return jsonify({})
    
    @app.route('/api/alerts')
    def get_alerts():
        """Get recent alerts."""
        if engine_ref["engine"] and engine_ref["engine"].alerts:
            alerts = engine_ref["engine"].alerts.get_alerts(limit=50)
            return jsonify(alerts)
        return jsonify([])
    
    @app.route('/api/capture/stats')
    def get_capture_stats():
        """Get capture statistics."""
        if engine_ref["engine"] and engine_ref["engine"].capture:
            stats = engine_ref["engine"].capture.get_statistics()
            return jsonify(stats)
        return jsonify({})
    
    @app.route('/api/health')
    def health():
        """Health check endpoint."""
        return jsonify({"status": "healthy"})
    
    return app
