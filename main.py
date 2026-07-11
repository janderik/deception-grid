#!/usr/bin/env python3
"""
Deception Grid - Advanced Honeypot Platform
Main entry point
"""

import argparse
import logging
import signal
import sys
import yaml
from pathlib import Path

from src.deception_grid.engine import DeceptionEngine, load_config, create_default_config
from src.honeypots import SSHHoneypot, HTTPHoneypot, DatabaseHoneypot, SMBHoneypot
from src.capture import TTPCapture, MITREMapper
from src.alerts import AlertManager, EmailAlert, WebhookAlert, SyslogAlert
from src.dashboard import create_app


def setup_logging(level: str = "INFO") -> None:
    """Configure logging."""
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('deception_grid.log')
        ]
    )


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Deception Grid - Advanced Honeypot Platform',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                    # Run with default config
  python main.py --config config.yaml  # Run with custom config
  python main.py --honeypots ssh,http  # Run specific honeypots only
  python main.py --dashboard --port 5000  # Enable web dashboard
        """
    )
    
    parser.add_argument('--config', '-c', help='Configuration file path')
    parser.add_argument('--honeypots', '-hp', help='Comma-separated list of honeypots to enable')
    parser.add_argument('--dashboard', '-d', action='store_true', help='Enable web dashboard')
    parser.add_argument('--port', '-p', type=int, default=5000, help='Dashboard port')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    
    args = parser.parse_args()
    
    # Load configuration
    if args.config and Path(args.config).exists():
        config = load_config(args.config)
    else:
        config = create_default_config()
    
    # Override dashboard settings
    if args.dashboard:
        config['dashboard'] = {'enabled': True, 'port': args.port}
    
    # Setup logging
    log_level = "DEBUG" if args.debug else config.get('engine', {}).get('log_level', 'INFO')
    setup_logging(log_level)
    
    logger = logging.getLogger('deception_grid')
    logger.info("Starting Deception Grid...")
    
    # Create engine
    engine = DeceptionEngine(config)
    
    # Setup capture
    if config.get('capture', {}).get('enabled', True):
        capture = TTPCapture(config.get('capture', {}))
        engine.set_capture(capture)
    
    # Setup alerts
    alert_config = config.get('alerts', {})
    alert_manager = AlertManager(alert_config)
    
    if alert_config.get('email', {}).get('enabled', False):
        alert_manager.register_handler(EmailAlert(alert_config['email']))
    
    if alert_config.get('webhook', {}).get('enabled', False):
        alert_manager.register_handler(WebhookAlert(alert_config['webhook']))
    
    if alert_config.get('syslog', {}).get('enabled', True):
        alert_manager.register_handler(SyslogAlert(alert_config.get('syslog', {})))
    
    engine.set_alerts(alert_manager)
    
    # Setup honeypots
    honeypot_config = config.get('honeypots', {})
    enabled_honeypots = args.honeypots.split(',') if args.honeypots else None
    
    honeypots_to_start = []
    
    if honeypot_config.get('ssh', {}).get('enabled', True):
        if not enabled_honeypots or 'ssh' in enabled_honeypots:
            ssh = SSHHoneypot(honeypot_config.get('ssh', {}), engine)
            engine.register_honeypot('ssh', ssh)
            honeypots_to_start.append(ssh)
    
    if honeypot_config.get('http', {}).get('enabled', True):
        if not enabled_honeypots or 'http' in enabled_honeypots:
            http = HTTPHoneypot(honeypot_config.get('http', {}), engine)
            engine.register_honeypot('http', http)
            honeypots_to_start.append(http)
    
    if honeypot_config.get('database', {}).get('enabled', True):
        if not enabled_honeypots or 'database' in enabled_honeypots:
            db = DatabaseHoneypot(honeypot_config.get('database', {}), engine)
            engine.register_honeypot('database', db)
            honeypots_to_start.append(db)
    
    if honeypot_config.get('smb', {}).get('enabled', True):
        if not enabled_honeypots or 'smb' in enabled_honeypots:
            smb = SMBHoneypot(honeypot_config.get('smb', {}), engine)
            engine.register_honeypot('smb', smb)
            honeypots_to_start.append(smb)
    
    # Start engine
    engine.start()
    
    # Start dashboard if enabled
    dashboard_app = None
    if config.get('dashboard', {}).get('enabled', False):
        dashboard_config = config.get('dashboard', {})
        dashboard_app = create_app(dashboard_config, engine)
        port = dashboard_config.get('port', 5000)
        logger.info(f"Dashboard starting on port {port}")
        
        from threading import Thread
        dashboard_thread = Thread(
            target=lambda: dashboard_app.run(host='0.0.0.0', port=port, debug=args.debug),
            daemon=True
        )
        dashboard_thread.start()
    
    # Signal handler
    def signal_handler(sig, frame):
        logger.info("Shutting down...")
        engine.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    logger.info("Deception Grid is running. Press Ctrl+C to stop.")
    logger.info(f"Active honeypots: {list(engine.honeypots.keys())}")
    
    # Keep running
    try:
        while True:
            signal.pause() if hasattr(signal, 'pause') else input()
    except KeyboardInterrupt:
        engine.stop()
        logger.info("Deception Grid stopped.")


if __name__ == '__main__':
    main()
