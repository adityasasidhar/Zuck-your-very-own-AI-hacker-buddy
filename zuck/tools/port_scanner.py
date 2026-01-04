"""
Python-native port scanner for quick reconnaissance.
"""

import json
import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple

from langchain.tools import tool

logger = logging.getLogger('zuck_agent')

# Common ports and their services
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    27017: "MongoDB"
}

TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 1723, 3306, 3389, 5432, 5900, 5985, 6379, 8080, 8443,
    8888, 9090, 9200, 9300, 27017, 27018, 28017, 50000, 50070, 50075
]


def scan_port(host: str, port: int, timeout: float = 1.0) -> Tuple[int, bool, str]:
    """Scan a single port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        
        if result == 0:
            service = COMMON_PORTS.get(port, "Unknown")
            return (port, True, service)
        return (port, False, "")
    except socket.error:
        return (port, False, "")


@tool
def port_scan(target: str, ports: str = "common", timeout: float = 1.0) -> str:
    """
    Scan ports on a target host using Python sockets.
    
    For more comprehensive scanning, use nmap.
    
    Args:
        target: Target IP or hostname
        ports: Port specification - 'common' (top 25), 'top100', '1-1000', '80,443,8080'
        timeout: Connection timeout in seconds (default: 1.0)
        
    Returns:
        Open ports and services
        
    Examples:
        port_scan("192.168.1.1")
        port_scan("scanme.nmap.org", "top100")
        port_scan("10.0.0.1", "22,80,443,3389")
    """
    try:
        # Resolve hostname
        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror:
            return f"Error: Could not resolve hostname: {target}"
        
        # Parse port specification
        if ports == "common":
            port_list = list(COMMON_PORTS.keys())
        elif ports == "top100":
            port_list = TOP_100_PORTS
        elif "-" in ports:
            # Range: "1-1000"
            start, end = map(int, ports.split("-"))
            port_list = list(range(start, min(end + 1, 65536)))
        elif "," in ports:
            # List: "80,443,8080"
            port_list = [int(p.strip()) for p in ports.split(",")]
        else:
            try:
                port_list = [int(ports)]
            except ValueError:
                return f"Error: Invalid port specification: {ports}"
        
        # Limit to 1000 ports per scan
        port_list = port_list[:1000]
        
        open_ports = []
        
        # Scan in parallel
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {
                executor.submit(scan_port, ip, port, timeout): port 
                for port in port_list
            }
            
            for future in as_completed(futures):
                port, is_open, service = future.result()
                if is_open:
                    open_ports.append({
                        "port": port,
                        "service": service,
                        "state": "open"
                    })
        
        # Sort by port number
        open_ports.sort(key=lambda x: x["port"])
        
        result = {
            "target": target,
            "ip": ip,
            "ports_scanned": len(port_list),
            "open_ports": len(open_ports),
            "ports": open_ports,
            "note": "For comprehensive scanning, use: nmap -sV -sC target"
        }
        
        return json.dumps(result, indent=2)
        
    except Exception as e:
        logger.error(f"Port scan error: {e}")
        return f"Error: {str(e)}"


@tool
def banner_grab(target: str, port: int, timeout: float = 3.0) -> str:
    """
    Grab service banner from a specific port.
    
    Args:
        target: Target IP or hostname
        port: Port number
        timeout: Timeout in seconds
        
    Returns:
        Service banner if available
        
    Examples:
        banner_grab("192.168.1.1", 22)
        banner_grab("example.com", 80)
    """
    try:
        # Resolve hostname
        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror:
            return f"Error: Could not resolve hostname: {target}"
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        try:
            sock.connect((ip, port))
            
            # For HTTP, send a request
            if port in [80, 8080, 8000, 8888]:
                sock.send(b"HEAD / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
            elif port == 443:
                # Can't grab HTTPS banner without SSL
                return json.dumps({
                    "target": target,
                    "port": port,
                    "note": "HTTPS port - use SSL tools for inspection"
                })
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            result = {
                "target": target,
                "ip": ip,
                "port": port,
                "banner": banner.strip()[:500],  # Limit banner size
                "service_guess": COMMON_PORTS.get(port, "Unknown")
            }
            
            return json.dumps(result, indent=2)
            
        except socket.error as e:
            return json.dumps({
                "target": target,
                "port": port,
                "error": f"Connection failed: {str(e)}"
            })
            
    except Exception as e:
        logger.error(f"Banner grab error: {e}")
        return f"Error: {str(e)}"


@tool
def ping_sweep(network: str) -> str:
    """
    Discover live hosts in a network range using TCP connect.
    
    Args:
        network: Network in CIDR notation (e.g., "192.168.1.0/24")
        
    Returns:
        List of live hosts
        
    Examples:
        ping_sweep("192.168.1.0/24")
    """
    import ipaddress
    
    try:
        # Parse network
        try:
            net = ipaddress.ip_network(network, strict=False)
        except ValueError as e:
            return f"Error: Invalid network: {e}"
        
        # Limit to /24 or smaller
        if net.num_addresses > 256:
            return "Error: Network too large. Maximum /24 (256 hosts)"
        
        live_hosts = []
        
        def check_host(ip):
            """Check if host responds on common ports."""
            ip_str = str(ip)
            for port in [80, 443, 22, 445]:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    result = sock.connect_ex((ip_str, port))
                    sock.close()
                    if result == 0:
                        return ip_str
                except:
                    pass
            return None
        
        # Scan in parallel
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(check_host, ip): ip for ip in net.hosts()}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    live_hosts.append(result)
        
        live_hosts.sort(key=lambda x: [int(p) for p in x.split('.')])
        
        result = {
            "network": network,
            "hosts_scanned": net.num_addresses - 2,
            "live_hosts": len(live_hosts),
            "hosts": live_hosts,
            "note": "For ICMP ping sweep, use: nmap -sn network"
        }
        
        return json.dumps(result, indent=2)
        
    except Exception as e:
        logger.error(f"Ping sweep error: {e}")
        return f"Error: {str(e)}"
