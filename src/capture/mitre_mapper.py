"""
MITRE ATT&CK Framework Mapper
"""

import logging
import json
from typing import Dict, Any, List, Optional
from pathlib import Path


class MITREMapper:
    """Maps detected behaviors to MITRE ATT&CK framework."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.logger = logging.getLogger("deception_grid.mitre")
        self.mitre_data = self._load_mitre_data()
    
    def _load_mitre_data(self) -> Dict[str, Any]:
        """Load MITRE ATT&CK data."""
        # Simplified MITRE ATT&CK mapping
        return {
            "tactics": {
                "TA0001": {
                    "name": "Initial Access",
                    "description": "The adversary is trying to gain access to your networks.",
                    "techniques": {
                        "T1133": {"name": "External Remote Services", "platforms": ["Linux", "Windows", "macOS"]},
                        "T1078": {"name": "Valid Accounts", "platforms": ["Linux", "Windows", "macOS"]},
                        "T1190": {"name": "Exploit Public-Facing Application", "platforms": ["Linux", "Windows"]}
                    }
                },
                "TA0002": {
                    "name": "Execution",
                    "description": "The adversary is trying to run malicious code.",
                    "techniques": {
                        "T1059": {"name": "Command and Scripting Interpreter", "platforms": ["Linux", "Windows", "macOS"]},
                        "T1203": {"name": "Exploitation for Client Execution", "platforms": ["Linux", "Windows"]}
                    }
                },
                "TA0003": {
                    "name": "Persistence",
                    "description": "The adversary is trying to maintain their foothold.",
                    "techniques": {
                        "T1053": {"name": "Scheduled Task/Job", "platforms": ["Linux", "Windows"]},
                        "T1543": {"name": "Create or Modify System Process", "platforms": ["Linux", "Windows"]}
                    }
                },
                "TA0004": {
                    "name": "Privilege Escalation",
                    "description": "The adversary is trying to gain higher-level permissions.",
                    "techniques": {
                        "T1548": {"name": "Abuse Elevation Control Mechanism", "platforms": ["Linux", "Windows"]},
                        "T1068": {"name": "Exploitation for Privilege Escalation", "platforms": ["Linux", "Windows"]}
                    }
                },
                "TA0005": {
                    "name": "Defense Evasion",
                    "description": "The adversary is trying to avoid being detected.",
                    "techniques": {
                        "T1070": {"name": "Indicator Removal", "platforms": ["Linux", "Windows"]},
                        "T1027": {"name": "Obfuscated Files or Information", "platforms": ["Linux", "Windows"]}
                    }
                },
                "TA0006": {
                    "name": "Credential Access",
                    "description": "The adversary is trying to steal account names and passwords.",
                    "techniques": {
                        "T1003": {"name": "OS Credential Dumping", "platforms": ["Linux", "Windows"]},
                        "T1110": {"name": "Brute Force", "platforms": ["Linux", "Windows"]}
                    }
                },
                "TA0007": {
                    "name": "Discovery",
                    "description": "The adversary is trying to figure out your environment.",
                    "techniques": {
                        "T1046": {"name": "Network Service Scanning", "platforms": ["Linux", "Windows"]},
                        "T1082": {"name": "System Information Discovery", "platforms": ["Linux", "Windows"]}
                    }
                },
                "TA0008": {
                    "name": "Lateral Movement",
                    "description": "The adversary is trying to move through your environment.",
                    "techniques": {
                        "T1021": {"name": "Remote Services", "platforms": ["Linux", "Windows"]},
                        "T1570": {"name": "Lateral Tool Transfer", "platforms": ["Linux", "Windows"]}
                    }
                },
                "TA0009": {
                    "name": "Collection",
                    "description": "The adversary is trying to gather data of interest.",
                    "techniques": {
                        "T1005": {"name": "Data from Local System", "platforms": ["Linux", "Windows"]},
                        "T1039": {"name": "Data from Network Shared Drive", "platforms": ["Linux", "Windows"]}
                    }
                },
                "TA0010": {
                    "name": "Exfiltration",
                    "description": "The adversary is trying to steal data.",
                    "techniques": {
                        "T1041": {"name": "Exfiltration Over C2 Channel", "platforms": ["Linux", "Windows"]},
                        "T1567": {"name": "Exfiltration Over Web Service", "platforms": ["Linux", "Windows"]}
                    }
                }
            }
        }
    
    def map_ttps_to_mitre(self, ttps: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Map detected TTPs to MITRE ATT&CK framework."""
        mapped = {
            "tactics": {},
            "techniques": [],
            "coverage_score": 0,
            "risk_assessment": "unknown"
        }
        
        tactic_mapping = {
            "initial_access": "TA0001",
            "execution": "TA0002",
            "persistence": "TA0003",
            "privilege_escalation": "TA0004",
            "defense_evasion": "TA0005",
            "credential_access": "TA0006",
            "discovery": "TA0007",
            "lateral_movement": "TA0008",
            "collection": "TA0009",
            "exfiltration": "TA0010"
        }
        
        for ttp in ttps:
            tactic_name = ttp.get("tactic", "")
            tactic_id = tactic_mapping.get(tactic_name)
            
            if tactic_id and tactic_id in self.mitre_data["tactics"]:
                tactic_info = self.mitre_data["tactics"][tactic_id]
                
                if tactic_id not in mapped["tactics"]:
                    mapped["tactics"][tactic_id] = {
                        "name": tactic_info["name"],
                        "description": tactic_info["description"],
                        "techniques": []
                    }
                
                mapped["tactics"][tactic_id]["techniques"].append({
                    "tactic": tactic_name,
                    "confidence": ttp.get("confidence", 0),
                    "source": ttp.get("source", "unknown")
                })
        
        # Calculate coverage score
        total_tactics = len(self.mitre_data["tactics"])
        covered_tactics = len(mapped["tactics"])
        mapped["coverage_score"] = (covered_tactics / total_tactics) * 100 if total_tactics > 0 else 0
        
        # Risk assessment
        if mapped["coverage_score"] > 60:
            mapped["risk_assessment"] = "critical"
        elif mapped["coverage_score"] > 40:
            mapped["risk_assessment"] = "high"
        elif mapped["coverage_score"] > 20:
            mapped["risk_assessment"] = "medium"
        else:
            mapped["risk_assessment"] = "low"
        
        return mapped
    
    def get_tactic_details(self, tactic_id: str) -> Optional[Dict[str, Any]]:
        """Get details for a specific tactic."""
        return self.mitre_data["tactics"].get(tactic_id)
    
    def get_technique_details(self, tactic_id: str, technique_id: str) -> Optional[Dict[str, Any]]:
        """Get details for a specific technique."""
        tactic = self.mitre_data["tactics"].get(tactic_id)
        if tactic:
            return tactic["techniques"].get(technique_id)
        return None
    
    def export_mapping(self, mapping: Dict[str, Any], format: str = "json") -> str:
        """Export MITRE mapping."""
        if format == "json":
            return json.dumps(mapping, indent=2)
        else:
            output = ["MITRE ATT&CK Mapping Report", "=" * 40, ""]
            
            for tactic_id, tactic_data in mapping.get("tactics", {}).items():
                output.append(f"{tactic_id}: {tactic_data['name']}")
                output.append(f"  {tactic_data['description']}")
                
                for technique in tactic_data.get("techniques", []):
                    output.append(f"  - Confidence: {technique['confidence']:.2f}")
                output.append("")
            
            output.append(f"Coverage Score: {mapping.get('coverage_score', 0):.1f}%")
            output.append(f"Risk Assessment: {mapping.get('risk_assessment', 'unknown')}")
            
            return "\n".join(output)
