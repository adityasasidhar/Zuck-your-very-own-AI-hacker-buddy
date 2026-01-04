"""
Incident Response playbook.
"""

import json
from langchain.tools import tool


@tool
def run_ir_playbook(incident_type: str = "general") -> str:
    """
    Run incident response playbook for security incidents.
    
    Performs: log analysis, process check, network analysis, IOC collection.
    
    Args:
        incident_type: Type - general, malware, intrusion, data_breach
        
    Returns:
        IR analysis results
        
    Examples:
        run_ir_playbook()
        run_ir_playbook("malware")
    """
    from zuck.tools.log_analyzer import analyze_auth_log
    from zuck.tools.system_monitor import analyze_processes, analyze_connections
    
    results = {"incident_type": incident_type, "phases": {}, "iocs": [], "recommendations": []}
    
    # Phase 1: Process analysis
    print(f"\n📋 Phase 1: Process Analysis")
    try:
        results["phases"]["processes"] = json.loads(analyze_processes.invoke({}))
    except:
        results["phases"]["processes"] = "Error"
    
    # Phase 2: Network connections
    print(f"📋 Phase 2: Network Analysis")
    try:
        results["phases"]["network"] = json.loads(analyze_connections.invoke({}))
    except:
        results["phases"]["network"] = "Error"
    
    # Phase 3: Auth log analysis
    print(f"📋 Phase 3: Authentication Log Analysis")
    try:
        results["phases"]["auth_logs"] = json.loads(analyze_auth_log.invoke({}))
    except:
        results["phases"]["auth_logs"] = "Error (need sudo)"
    
    # Collect IOCs
    proc_result = results["phases"].get("processes", {})
    if isinstance(proc_result, dict):
        suspicious = proc_result.get("suspicious", [])
        for s in suspicious:
            results["iocs"].append({"type": "process", "value": s.get("cmd", "")[:50]})
    
    # Generate recommendations based on incident type
    if incident_type == "malware":
        results["recommendations"] = [
            "Isolate affected system from network",
            "Capture memory dump: sudo dd if=/dev/mem of=memdump.raw",
            "Check for persistence: crontab -l, ls /etc/cron.*",
            "Scan with ClamAV: clamscan -r /",
            "Check startup items: systemctl list-unit-files | grep enabled"
        ]
    elif incident_type == "intrusion":
        results["recommendations"] = [
            "Check SSH authorized_keys: cat ~/.ssh/authorized_keys",
            "Review sudo logs: grep sudo /var/log/auth.log",
            "Check for new users: cat /etc/passwd",
            "Look for SUID binaries: find / -perm -4000 2>/dev/null",
            "Check network listeners: ss -tlnp"
        ]
    else:
        results["recommendations"] = [
            "Preserve evidence: Create disk image",
            "Document timeline of events",
            "Check for unusual files in /tmp",
            "Review cron jobs: ls -la /etc/cron*",
            "Check bash history: cat ~/.bash_history"
        ]
    
    return json.dumps(results, indent=2)
