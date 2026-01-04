"""
Process and network monitoring tools.
"""

import json
import logging
import re
import subprocess
from langchain.tools import tool

logger = logging.getLogger('zuck_agent')


@tool
def analyze_processes() -> str:
    """
    Analyze running processes for suspicious activity.
    
    Returns:
        Process analysis with suspicious indicators
    """
    try:
        result = subprocess.run(
            ["ps", "aux"], capture_output=True, text=True, timeout=10
        )
        
        lines = result.stdout.strip().split('\n')[1:]
        
        suspicious = []
        high_cpu = []
        high_mem = []
        
        suspicious_patterns = [
            r"nc\s+-", r"ncat", r"netcat",  # Netcat
            r"\/tmp\/", r"\/dev\/shm",      # Suspicious paths
            r"base64", r"curl.*\|.*sh",     # Download and execute
            r"python.*-c", r"perl.*-e",     # One-liners
            r"cryptominer", r"xmrig"        # Crypto miners
        ]
        
        for line in lines:
            parts = line.split()
            if len(parts) >= 11:
                user, pid, cpu, mem = parts[0], parts[1], float(parts[2]), float(parts[3])
                cmd = ' '.join(parts[10:])
                
                proc = {"pid": pid, "user": user, "cpu": cpu, "mem": mem, "cmd": cmd[:100]}
                
                if cpu > 80:
                    high_cpu.append(proc)
                if mem > 20:
                    high_mem.append(proc)
                
                for pattern in suspicious_patterns:
                    if re.search(pattern, cmd, re.IGNORECASE):
                        proc["pattern_matched"] = pattern
                        suspicious.append(proc)
                        break
        
        return json.dumps({
            "total_processes": len(lines),
            "high_cpu": high_cpu[:5],
            "high_memory": high_mem[:5],
            "suspicious": suspicious,
            "suspicious_count": len(suspicious)
        }, indent=2)
        
    except Exception as e:
        return f"Error: {e}"


@tool
def analyze_connections() -> str:
    """
    Analyze network connections for suspicious activity.
    
    Returns:
        Network connection analysis
    """
    try:
        result = subprocess.run(
            ["ss", "-tunapl"], capture_output=True, text=True, timeout=10
        )
        
        connections = []
        listening = []
        established = []
        
        for line in result.stdout.strip().split('\n')[1:]:
            parts = line.split()
            if len(parts) >= 5:
                state = parts[0]
                local = parts[4] if len(parts) > 4 else ""
                remote = parts[5] if len(parts) > 5 else ""
                
                conn = {"state": state, "local": local, "remote": remote}
                connections.append(conn)
                
                if "LISTEN" in state:
                    listening.append(local)
                elif "ESTAB" in state:
                    established.append(conn)
        
        # Check for suspicious ports
        suspicious_ports = ["4444", "5555", "6666", "1337", "31337"]
        suspicious = [c for c in connections if any(p in c.get("local", "") for p in suspicious_ports)]
        
        return json.dumps({
            "total_connections": len(connections),
            "listening_ports": listening[:20],
            "established": len(established),
            "suspicious_ports": suspicious
        }, indent=2)
        
    except Exception as e:
        return f"Error: {e}"


@tool
def check_open_ports() -> str:
    """
    Check for open listening ports on localhost.
    
    Returns:
        List of open ports and services
    """
    try:
        result = subprocess.run(
            ["ss", "-tlnp"], capture_output=True, text=True, timeout=10
        )
        
        ports = []
        for line in result.stdout.strip().split('\n')[1:]:
            parts = line.split()
            if len(parts) >= 4:
                local = parts[3]
                process = parts[-1] if "users:" in parts[-1] else ""
                
                # Extract port
                port_match = re.search(r':(\d+)$', local)
                if port_match:
                    ports.append({
                        "port": port_match.group(1),
                        "address": local,
                        "process": process[:50]
                    })
        
        return json.dumps({
            "open_ports": len(ports),
            "ports": sorted(ports, key=lambda x: int(x["port"]))
        }, indent=2)
        
    except Exception as e:
        return f"Error: {e}"
