"""
Playbooks module - Automated security workflows.
"""

from zuck.playbooks.recon import run_recon_playbook
from zuck.playbooks.web_pentest import run_web_pentest
from zuck.playbooks.incident_response import run_ir_playbook

__all__ = [
    "run_recon_playbook",
    "run_web_pentest",
    "run_ir_playbook",
]
