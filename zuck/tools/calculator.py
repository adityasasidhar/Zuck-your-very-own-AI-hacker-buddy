"""
Network calculator tool.
"""

import re
import json
import ipaddress
import logging

from langchain.tools import tool

logger = logging.getLogger('zuck_agent')


@tool
def calculator(expression: str) -> str:
    """
    Evaluate mathematical expressions and perform network calculations.
    
    Supports:
    - Basic math: 2+2, 10*5, 100/4
    - Subnet calculations: "192.168.1.0/24 size", "10.0.0.0/16 range"
    - Hex/decimal conversions: "0xFF to decimal", "255 to hex"
    - Binary conversions: "0b11111111 to decimal", "255 to binary"
    - Port calculations: "1024 + 80"
    
    Args:
        expression: Mathematical expression or network calculation
        
    Returns:
        Calculation result as string
        
    Examples:
        calculator("2 + 2") -> "4"
        calculator("192.168.1.0/24 size") -> "256 addresses"
        calculator("0xFF to decimal") -> "255"
    """
    try:
        expression = expression.strip().lower()
        
        # Subnet calculations
        if '/' in expression and any(word in expression for word in ['size', 'range', 'hosts', 'network']):
            # Extract CIDR notation
            cidr_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})', expression)
            if cidr_match:
                network = ipaddress.ip_network(cidr_match.group(1), strict=False)
                result = {
                    "network": str(network.network_address),
                    "netmask": str(network.netmask),
                    "broadcast": str(network.broadcast_address),
                    "first_host": str(list(network.hosts())[0]) if network.num_addresses > 2 else "N/A",
                    "last_host": str(list(network.hosts())[-1]) if network.num_addresses > 2 else "N/A",
                    "total_addresses": network.num_addresses,
                    "usable_hosts": network.num_addresses - 2 if network.num_addresses > 2 else 0
                }
                return json.dumps(result, indent=2)
        
        # Hex to decimal
        if 'to decimal' in expression or 'to dec' in expression:
            hex_match = re.search(r'0x([0-9a-f]+)', expression)
            if hex_match:
                return str(int(hex_match.group(1), 16))
        
        # Decimal to hex
        if 'to hex' in expression:
            dec_match = re.search(r'(\d+)', expression)
            if dec_match:
                return hex(int(dec_match.group(1)))
        
        # Binary to decimal
        if 'to decimal' in expression or 'to dec' in expression:
            bin_match = re.search(r'0b([01]+)', expression)
            if bin_match:
                return str(int(bin_match.group(1), 2))
        
        # Decimal to binary
        if 'to binary' in expression or 'to bin' in expression:
            dec_match = re.search(r'(\d+)', expression)
            if dec_match:
                return bin(int(dec_match.group(1)))
        
        # Basic math evaluation (safe eval)
        # Remove any non-math characters for safety
        safe_expr = re.sub(r'[^0-9+\-*/().\s]', '', expression)
        if safe_expr:
            result = eval(safe_expr, {"__builtins__": {}}, {})
            return str(result)
        
        return "Unable to parse expression. Try: '2+2', '192.168.1.0/24 size', '0xFF to decimal'"
        
    except Exception as e:
        logger.error(f"Calculator error: {e}")
        return f"Error: {str(e)}"
