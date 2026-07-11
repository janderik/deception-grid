"""
TTP (Tactics, Techniques, and Procedures) Capture Module
"""

import logging
import json
from typing import Dict, Any, List, Optional
from datetime import datetime
from collections import defaultdict


class TTPCapture:
    """Captures and analyzes attacker TTPs."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger("deception_grid.capture")
        self.mitre_mapping = config.get("mitre_mapping", True)
        self.events = []
        self.sessions = defaultdict(list)
        self._patterns = self._load_patterns()
    
    def _load_patterns(self) -> Dict[str, Any]:
        """Load TTP detection patterns."""
        return {
            "reconnaissance": {
                "keywords": ["nmap", "masscan", "zmap", "scan", "port"],
                "patterns": [r"SYN", r"ACK", r"FIN"]
            },
            "initial_access": {
                "keywords": ["admin", "root", "login", "password", "brute"],
                "patterns": [r"ssh.*password", r"http.*login"]
            },
            "execution": {
                "keywords": ["cmd", "bash", "exec", "eval", "system"],
                "patterns": [r";\s*ls", r"&&\s*whoami", r"\|\s*cat"]
            },
            "persistence": {
                "keywords": ["crontab", "systemd", "startup", "autorun"],
                "patterns": [r"echo.*>>.*crontab", r"systemctl.*enable"]
            },
            "privilege_escalation": {
                "keywords": ["sudo", "su", "chmod", "chown", "setuid"],
                "patterns": [r"chmod\s+[47]", r"chown\s+root"]
            },
            "defense_evasion": {
                "keywords": ["hide", "delete", "clear", "history"],
                "patterns": [r"rm\s+-rf", r"history\s+-c", r">.*\.log"]
            },
            "credential_access": {
                "keywords": ["shadow", "passwd", "key", "token", "cookie"],
                "patterns": [r"/etc/shadow", r"\.ssh/.*key"]
            },
            "discovery": {
                "keywords": ["whoami", "ifconfig", "netstat", "ps", "ls"],
                "patterns": [r"whoami", r"ifconfig|ip\s+a", r"netstat"]
            },
            "lateral_movement": {
                "keywords": ["ssh", "scp", "psexec", "winrm"],
                "patterns": [r"ssh\s+.*@", r"scp\s+"]
            },
            "collection": {
                "keywords": ["tar", "zip", "compress", "download", "wget"],
                "patterns": [r"tar\s+.*czf", r"wget\s+", r"curl\s+"]
            },
            "exfiltration": {
                "keywords": ["upload", "scp", "ftp", "http.*post"],
                "patterns": [r"curl.*-d", r"wget.*--post"]
            }
        }
    
    def process_event(self, event: Any) -> None:
        """Process a honeypot event for TTP extraction."""
        event_dict = event.to_dict() if hasattr(event, 'to_dict') else event
        self.events.append(event_dict)
        
        # Create session key
        src_ip = event_dict.get("data", {}).get("src_ip", "unknown")
        self.sessions[src_ip].append(event_dict)
        
        # Analyze for TTPs
        ttps = self._analyze_ttps(event_dict)
        
        if ttps:
            self.logger.info(f"Detected TTPs from {src_ip}: {[t['name'] for t in ttps]}")
            
            # Store TTPs in event
            event_dict["detected_ttps"] = ttps
    
    def _analyze_ttps(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze event for TTP patterns."""
        detected = []
        data = event.get("data", {})
        
        # Combine all text data for analysis
        text_data = " ".join([
            str(data.get("path", "")),
            str(data.get("body_preview", "")),
            str(data.get("command", "")),
            str(data.get("password", "")),
            str(data.get("username", ""))
        ]).lower()
        
        # Check patterns
        for tactic, patterns in self._patterns.items():
            score = 0
            matched_keywords = []
            matched_patterns = []
            
            # Check keywords
            for keyword in patterns["keywords"]:
                if keyword in text_data:
                    score += 1
                    matched_keywords.append(keyword)
            
            # Check regex patterns
            import re
            for pattern in patterns["patterns"]:
                if re.search(pattern, text_data):
                    score += 1
                    matched_patterns.append(pattern)
            
            if score > 0:
                detected.append({
                    "tactic": tactic,
                    "name": tactic.replace("_", " ").title(),
                    "confidence": min(score / 3, 1.0),
                    "matched_keywords": matched_keywords,
                    "matched_patterns": matched_patterns,
                    "source": event.get("source", "unknown")
                })
        
        return detected
    
    def get_session_ttps(self, src_ip: str) -> List[Dict[str, Any]]:
        """Get all TTPs for a specific source IP."""
        session_events = self.sessions.get(src_ip, [])
        all_ttps = []
        
        for event in session_events:
            ttps = event.get("detected_ttps", [])
            all_ttps.extend(ttps)
        
        return all_ttps
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get capture statistics."""
        tactic_counts = defaultdict(int)
        source_counts = defaultdict(int)
        
        for event in self.events:
            ttps = event.get("detected_ttps", [])
            src_ip = event.get("data", {}).get("src_ip", "unknown")
            source_counts[src_ip] += 1
            
            for ttp in ttps:
                tactic_counts[ttp["tactic"]] += 1
        
        return {
            "total_events": len(self.events),
            "unique_sources": len(self.sessions),
            "tactic_distribution": dict(tactic_counts),
            "top_sources": sorted(source_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        }
    
    def export_ttps(self, format: str = "json") -> str:
        """Export captured TTPs."""
        if format == "json":
            return json.dumps(self.events, indent=2, default=str)
        else:
            # Plain text format
            output = []
            for event in self.events:
                ttps = event.get("detected_ttps", [])
                if ttps:
                    src_ip = event.get("data", {}).get("src_ip", "unknown")
                    output.append(f"Source: {src_ip}")
                    output.append(f"Time: {event.get('timestamp', 'unknown')}")
                    for ttp in ttps:
                        output.append(f"  - {ttp['name']} (confidence: {ttp['confidence']:.2f})")
                    output.append("")
            return "\n".join(output)
