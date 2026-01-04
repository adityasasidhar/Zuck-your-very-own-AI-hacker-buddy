"""
Knowledge base module - Security reference information.
"""

from zuck.knowledge.mitre_attack import get_attack_technique, search_techniques
from zuck.knowledge.owasp import get_owasp_info

__all__ = [
    "get_attack_technique",
    "search_techniques",
    "get_owasp_info",
]
