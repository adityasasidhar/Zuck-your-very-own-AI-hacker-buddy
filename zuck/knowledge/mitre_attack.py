"""
MITRE ATT&CK framework reference.
"""

import json
from langchain.tools import tool

# Subset of MITRE ATT&CK techniques
ATTACK_TECHNIQUES = {
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters to execute commands.",
        "subtechniques": ["T1059.001 PowerShell", "T1059.003 Windows Command Shell", "T1059.004 Unix Shell"],
        "mitigations": ["Disable unused interpreters", "Enable script logging", "Use application control"]
    },
    "T1055": {
        "name": "Process Injection",
        "tactic": "Defense Evasion, Privilege Escalation",
        "description": "Adversaries may inject code into processes to evade defenses.",
        "subtechniques": ["T1055.001 DLL Injection", "T1055.002 Portable Executable Injection"],
        "mitigations": ["Endpoint detection", "Behavior monitoring"]
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Defense Evasion, Initial Access",
        "description": "Adversaries may obtain and abuse credentials of existing accounts.",
        "subtechniques": ["T1078.001 Default Accounts", "T1078.002 Domain Accounts"],
        "mitigations": ["MFA", "Password policies", "Account monitoring"]
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force to access accounts.",
        "subtechniques": ["T1110.001 Password Guessing", "T1110.002 Password Cracking", "T1110.003 Password Spraying"],
        "mitigations": ["Account lockout", "MFA", "Rate limiting"]
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries may exploit vulnerabilities in public-facing apps.",
        "mitigations": ["Patch management", "WAF", "Network segmentation"]
    },
    "T1021": {
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use remote services to move laterally.",
        "subtechniques": ["T1021.001 RDP", "T1021.002 SMB", "T1021.004 SSH"],
        "mitigations": ["Limit remote access", "MFA", "Network segmentation"]
    }
}


@tool
def get_attack_technique(technique_id: str) -> str:
    """
    Get MITRE ATT&CK technique information.
    
    Args:
        technique_id: MITRE technique ID (e.g., T1059)
        
    Returns:
        Technique details
    """
    technique_id = technique_id.upper().strip()
    
    if technique_id in ATTACK_TECHNIQUES:
        result = ATTACK_TECHNIQUES[technique_id].copy()
        result["id"] = technique_id
        result["url"] = f"https://attack.mitre.org/techniques/{technique_id}/"
        return json.dumps(result, indent=2)
    
    return json.dumps({
        "error": f"Technique not found: {technique_id}",
        "available": list(ATTACK_TECHNIQUES.keys())
    })


@tool
def search_techniques(keyword: str) -> str:
    """
    Search MITRE ATT&CK techniques by keyword.
    
    Args:
        keyword: Search term
        
    Returns:
        Matching techniques
    """
    keyword = keyword.lower()
    matches = []
    
    for tid, tech in ATTACK_TECHNIQUES.items():
        if (keyword in tech["name"].lower() or 
            keyword in tech["description"].lower() or
            keyword in tech["tactic"].lower()):
            matches.append({"id": tid, "name": tech["name"], "tactic": tech["tactic"]})
    
    return json.dumps({"keyword": keyword, "matches": matches}, indent=2)
