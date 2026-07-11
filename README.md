# Deception Grid

[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-orange)]()
[![Maintenance](https://img.shields.io/badge/maintenance-active-blue)]()

> An advanced honeypot platform for detecting, analyzing, and responding to cyber threats using deception technology.

```
┌─────────────────────────────────────────────────────────────────┐
│                     DECEPTION GRID ARCHITECTURE                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐  │
│  │ SSH      │    │ HTTP     │    │ Database │    │ SMB      │  │
│  │ Honeypot │    │ Honeypot │    │ Honeypot │    │ Honeypot │  │
│  └────┬─────┘    └────┬─────┘    └────┬─────┘    └────┬─────┘  │
│       │               │               │               │        │
│       └───────────────┴───────┬───────┴───────────────┘        │
│                               │                                │
│                    ┌──────────▼──────────┐                     │
│                    │   Core Engine       │                     │
│                    │   (Event Router)    │                     │
│                    └──────────┬──────────┘                     │
│                               │                                │
│              ┌────────────────┼────────────────┐               │
│              │                │                │               │
│      ┌───────▼──────┐ ┌──────▼───────┐ ┌──────▼──────┐       │
│      │ TTP Capture  │ │ MITRE ATT&CK │ │   Alert     │       │
│      │   Module     │ │   Mapping    │ │   System    │       │
│      └──────────────┘ └──────────────┘ └──────┬──────┘       │
│                                                │              │
│                                      ┌─────────▼─────────┐    │
│                                      │ Flask Dashboard   │    │
│                                      │ (Web Interface)   │    │
│                                      └───────────────────┘    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Features

- **Multi-Protocol Honeypots**: SSH, HTTP, Database (MySQL/PostgreSQL), and SMB honeypot modules
- **TTP Capture**: Automatically captures attacker Tactics, Techniques, and Procedures
- **MITRE ATT&CK Mapping**: Maps captured behaviors to the MITRE ATT&CK framework
- **Real-time Dashboard**: Flask-based web interface for monitoring and analysis
- **Alert System**: Configurable alerts via email, webhook, and syslog
- **Plugin Architecture**: Easy to extend with custom honeypot modules
- **Low Interaction Mode**: Safe by design - attackers cannot escape the honeypot

## Quick Start

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Installation

```bash
# Clone the repository
git clone https://github.com/janderik/deception-grid.git
cd deception-grid

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
```

### Running

```bash
# Start with default configuration
python main.py

# Start with custom config
python main.py --config config.yaml

# Start specific honeypots only
python main.py --honeypots ssh,http

# Run in dashboard mode (web UI on port 5000)
python main.py --dashboard --port 5000
```

### Docker

```bash
# Build and run with Docker Compose
docker-compose up -d

# Or build manually
docker build -t deception-grid .
docker run -p 2222:22 -p 8080:80 -p 5000:5000 deception-grid
```

## Configuration

Create a `config.yaml` file:

```yaml
engine:
  log_level: INFO
  max_connections: 1000

honeypots:
  ssh:
    enabled: true
    port: 2222
    banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
    
  http:
    enabled: true
    port: 8080
    fake_pages:
      - admin
      - login
      - api
    
  database:
    enabled: true
    port: 3306
    type: mysql
    fake_databases:
      - users
      - credentials
    
  smb:
    enabled: true
    port: 445
    share_name: "Public"

capture:
  enabled: true
  mitre_mapping: true
  
alerts:
  email:
    enabled: false
    smtp_server: "smtp.example.com"
    recipients:
      - "security@example.com"
  webhook:
    enabled: false
    url: "https://hooks.slack.com/..."
  syslog:
    enabled: true
    server: "localhost"
    port: 514

dashboard:
  enabled: true
  port: 5000
  auth:
    enabled: true
    username: "admin"
    password: "changeme"
```

## Architecture

The Deception Grid follows a modular architecture:

1. **Core Engine**: Routes events between honeypots, capture modules, and alert systems
2. **Honeypot Modules**: Protocol-specific implementations that simulate real services
3. **TTP Capture**: Records attacker behavior and maps to MITRE ATT&CK
4. **Alert System**: Multi-channel notification system
5. **Dashboard**: Real-time monitoring and management interface

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is designed for defensive security purposes only. Users are responsible for ensuring they have proper authorization before deploying honeypots. Always check local laws and regulations regarding deception technology deployment.
