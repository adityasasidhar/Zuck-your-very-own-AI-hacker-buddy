"""
OWASP Top 10 reference.
"""

import json
from langchain.tools import tool

OWASP_TOP_10 = {
    "A01": {
        "name": "Broken Access Control",
        "description": "Restrictions on authenticated users are not properly enforced.",
        "examples": ["IDOR", "Privilege escalation", "Metadata manipulation"],
        "prevention": ["Deny by default", "Implement access control", "Log access failures"]
    },
    "A02": {
        "name": "Cryptographic Failures",
        "description": "Failures related to cryptography leading to data exposure.",
        "examples": ["Weak algorithms", "Hardcoded keys", "Missing encryption"],
        "prevention": ["Use strong algorithms", "Encrypt sensitive data", "Proper key management"]
    },
    "A03": {
        "name": "Injection",
        "description": "Untrusted data is sent to an interpreter as part of a command.",
        "examples": ["SQL injection", "XSS", "Command injection", "LDAP injection"],
        "prevention": ["Parameterized queries", "Input validation", "Escape special characters"]
    },
    "A04": {
        "name": "Insecure Design",
        "description": "Missing or ineffective security controls in design phase.",
        "examples": ["Missing threat modeling", "Insecure patterns", "Missing security req"],
        "prevention": ["Secure SDLC", "Threat modeling", "Security requirements"]
    },
    "A05": {
        "name": "Security Misconfiguration",
        "description": "Missing security hardening or improperly configured permissions.",
        "examples": ["Default credentials", "Open cloud storage", "Verbose errors"],
        "prevention": ["Hardening process", "Minimal installation", "Configuration review"]
    },
    "A06": {
        "name": "Vulnerable Components",
        "description": "Using components with known vulnerabilities.",
        "examples": ["Outdated libraries", "Unpatched software", "Unsupported components"],
        "prevention": ["Dependency scanning", "Regular updates", "Monitor CVEs"]
    },
    "A07": {
        "name": "Auth and Session Failures",
        "description": "Identity, authentication, and session management weaknesses.",
        "examples": ["Weak passwords", "Session fixation", "Missing MFA"],
        "prevention": ["Strong password policy", "MFA", "Secure session management"]
    },
    "A08": {
        "name": "Software & Data Integrity Failures",
        "description": "Code and infrastructure without integrity verification.",
        "examples": ["Insecure CI/CD", "Auto-update without verification", "Insecure deserialization"],
        "prevention": ["Digital signatures", "Integrity verification", "Secure pipelines"]
    },
    "A09": {
        "name": "Security Logging Failures",
        "description": "Insufficient logging, monitoring, and alerting.",
        "examples": ["Missing logs", "No alerting", "Logs not monitored"],
        "prevention": ["Log security events", "Monitor logs", "Incident response plan"]
    },
    "A10": {
        "name": "Server-Side Request Forgery",
        "description": "Web app fetches remote resource without validating URL.",
        "examples": ["Internal port scanning", "Cloud metadata access", "Internal service access"],
        "prevention": ["Input validation", "URL allowlisting", "Network segmentation"]
    }
}


@tool
def get_owasp_info(category: str) -> str:
    """
    Get OWASP Top 10 category information.
    
    Args:
        category: OWASP category (A01-A10) or keyword
        
    Returns:
        Category details and prevention
    """
    category = category.upper().strip()
    
    # Direct lookup
    if category in OWASP_TOP_10:
        result = OWASP_TOP_10[category].copy()
        result["id"] = category
        return json.dumps(result, indent=2)
    
    # Search by keyword
    keyword = category.lower()
    for cat_id, info in OWASP_TOP_10.items():
        if keyword in info["name"].lower() or keyword in info["description"].lower():
            result = info.copy()
            result["id"] = cat_id
            return json.dumps(result, indent=2)
    
    return json.dumps({
        "error": f"Category not found: {category}",
        "available": [f"{k}: {v['name']}" for k, v in OWASP_TOP_10.items()]
    }, indent=2)
