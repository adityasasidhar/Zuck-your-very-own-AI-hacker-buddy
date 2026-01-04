"""
Tool registry - Central place to manage all available tools.
"""

from typing import List, Optional, Any
import logging

logger = logging.getLogger('zuck_agent')

# Session memory storage (shared across tools)
_session_memory = {}


def get_session_memory():
    """Get the shared session memory."""
    return _session_memory


def clear_session_memory():
    """Clear the shared session memory."""
    global _session_memory
    _session_memory = {}


def get_all_tools() -> List[Any]:
    """
    Get list of all available tools.
    
    Returns:
        List of LangChain tool objects
    """
    tools = []
    
    # === Original Tools ===
    from zuck.tools.calculator import calculator
    from zuck.tools.virustotal import virustotal_lookup
    from zuck.tools.datetime_tool import datetime_tool
    from zuck.tools.memory import memory_store
    from zuck.tools.file_reader import read_file
    from zuck.tools.http import http_request
    from zuck.tools.dns import dns_lookup
    from zuck.tools.whois import whois_lookup
    from zuck.tools.python_repl import get_python_repl_tool
    from zuck.tools.wikipedia import wikipedia_search
    
    tools.extend([
        calculator, virustotal_lookup, datetime_tool, memory_store,
        read_file, http_request, dns_lookup, whois_lookup,
        get_python_repl_tool(), wikipedia_search
    ])
    
    # === OSINT Tools ===
    from zuck.tools.shodan import shodan_host_lookup, shodan_search
    from zuck.tools.subdomain_finder import find_subdomains, dns_subdomain_bruteforce
    from zuck.tools.ip_geolocation import ip_geolocation, bulk_ip_lookup
    from zuck.tools.social_analyzer import username_search, email_osint
    
    tools.extend([
        shodan_host_lookup, shodan_search,
        find_subdomains, dns_subdomain_bruteforce,
        ip_geolocation, bulk_ip_lookup,
        username_search, email_osint
    ])
    
    # === Offensive Tools ===
    from zuck.tools.exploit_db import cve_lookup, search_exploits, exploit_info
    from zuck.tools.payload_generator import generate_reverse_shell, encode_payload, generate_webshell
    from zuck.tools.hash_cracker import identify_hash, hash_string, generate_wordlist_command
    from zuck.tools.port_scanner import port_scan, banner_grab, ping_sweep
    from zuck.tools.sql_injection import sqli_payloads, generate_sqlmap_command
    
    tools.extend([
        cve_lookup, search_exploits, exploit_info,
        generate_reverse_shell, encode_payload, generate_webshell,
        identify_hash, hash_string, generate_wordlist_command,
        port_scan, banner_grab, ping_sweep,
        sqli_payloads, generate_sqlmap_command
    ])
    
    # === Defensive Tools ===
    from zuck.tools.log_analyzer import analyze_auth_log, analyze_web_log, search_logs
    from zuck.tools.system_monitor import analyze_processes, analyze_connections, check_open_ports
    from zuck.tools.ioc_extractor import extract_iocs, extract_iocs_from_file, analyze_file_hashes
    from zuck.tools.ssl_analyzer import analyze_ssl, analyze_security_headers
    
    tools.extend([
        analyze_auth_log, analyze_web_log, search_logs,
        analyze_processes, analyze_connections, check_open_ports,
        extract_iocs, extract_iocs_from_file, analyze_file_hashes,
        analyze_ssl, analyze_security_headers
    ])
    
    # === Playbooks ===
    from zuck.playbooks.recon import run_recon_playbook
    from zuck.playbooks.web_pentest import run_web_pentest
    from zuck.playbooks.incident_response import run_ir_playbook
    
    tools.extend([
        run_recon_playbook, run_web_pentest, run_ir_playbook
    ])
    
    # === Knowledge Base ===
    from zuck.knowledge.mitre_attack import get_attack_technique, search_techniques
    from zuck.knowledge.owasp import get_owasp_info
    
    tools.extend([
        get_attack_technique, search_techniques, get_owasp_info
    ])
    
    # === Shell Execution ===
    from zuck.tools.shell import (
        shell_run, shell_run_background, shell_status,
        shell_terminate, shell_list
    )
    
    tools.extend([
        shell_run, shell_run_background, shell_status,
        shell_terminate, shell_list
    ])
    
    # === Planning ===
    from zuck.tools.planner import create_plan, update_plan_step, get_current_plan
    tools.extend([create_plan, update_plan_step, get_current_plan])
    
    logger.info(f"Loaded {len(tools)} tools")
    return tools


def get_tool_by_name(name: str) -> Optional[Any]:
    """
    Get a specific tool by name.
    
    Args:
        name: Name of the tool to retrieve
        
    Returns:
        Tool object or None if not found
    """
    tools = get_all_tools()
    for tool in tools:
        if tool.name == name:
            return tool
    return None


def list_tools() -> List[str]:
    """Get list of all tool names."""
    return [tool.name for tool in get_all_tools()]
