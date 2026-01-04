"""
Hash identification and cracking helper tool.
"""

import json
import logging
import re
import hashlib

from langchain.tools import tool

logger = logging.getLogger('zuck_agent')

# Common hash patterns
HASH_PATTERNS = [
    ("MD5", r"^[a-fA-F0-9]{32}$"),
    ("SHA1", r"^[a-fA-F0-9]{40}$"),
    ("SHA256", r"^[a-fA-F0-9]{64}$"),
    ("SHA512", r"^[a-fA-F0-9]{128}$"),
    ("NTLM", r"^[a-fA-F0-9]{32}$"),
    ("MySQL 4.1+", r"^\*[A-F0-9]{40}$"),
    ("MD5 Unix", r"^\$1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{22}$"),
    ("SHA256 Unix", r"^\$5\$[a-zA-Z0-9./]{16}\$[a-zA-Z0-9./]{43}$"),
    ("SHA512 Unix", r"^\$6\$[a-zA-Z0-9./]{16}\$[a-zA-Z0-9./]{86}$"),
    ("bcrypt", r"^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$"),
    ("Argon2", r"^\$argon2(i|d|id)\$.*$"),
    ("DES Unix", r"^[a-zA-Z0-9./]{13}$"),
    ("MD5 APR1", r"^\$apr1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{22}$"),
    ("LM", r"^[a-fA-F0-9]{32}$"),
    ("Cisco Type 5", r"^\$1\$[a-zA-Z0-9./]{4}\$[a-zA-Z0-9./]{22}$"),
    ("Cisco Type 7", r"^[0-9]{2}[a-fA-F0-9]+$"),
]

# Hashcat mode mappings
HASHCAT_MODES = {
    "MD5": 0,
    "SHA1": 100,
    "SHA256": 1400,
    "SHA512": 1700,
    "NTLM": 1000,
    "bcrypt": 3200,
    "MD5 Unix": 500,
    "SHA256 Unix": 7400,
    "SHA512 Unix": 1800,
    "MySQL 4.1+": 300,
    "LM": 3000,
}

# John the Ripper format mappings
JOHN_FORMATS = {
    "MD5": "Raw-MD5",
    "SHA1": "Raw-SHA1",
    "SHA256": "Raw-SHA256",
    "SHA512": "Raw-SHA512",
    "NTLM": "NT",
    "bcrypt": "bcrypt",
    "MD5 Unix": "md5crypt",
    "SHA256 Unix": "sha256crypt",
    "SHA512 Unix": "sha512crypt",
    "MySQL 4.1+": "mysql-sha1",
    "LM": "LM",
}


@tool
def identify_hash(hash_value: str) -> str:
    """
    Identify the type of a hash value.
    
    Args:
        hash_value: Hash string to identify
        
    Returns:
        Possible hash types with cracking suggestions
        
    Examples:
        identify_hash("5d41402abc4b2a76b9719d911017c592")
        identify_hash("$6$rounds=5000$salt$...")
    """
    try:
        hash_value = hash_value.strip()
        
        possible_types = []
        
        for hash_type, pattern in HASH_PATTERNS:
            if re.match(pattern, hash_value):
                possible_types.append({
                    "type": hash_type,
                    "hashcat_mode": HASHCAT_MODES.get(hash_type, "Unknown"),
                    "john_format": JOHN_FORMATS.get(hash_type, "Unknown")
                })
        
        # Special case: 32 char could be MD5 or NTLM
        if len(hash_value) == 32 and re.match(r'^[a-fA-F0-9]+$', hash_value):
            possible_types = [
                {"type": "MD5", "hashcat_mode": 0, "john_format": "Raw-MD5"},
                {"type": "NTLM", "hashcat_mode": 1000, "john_format": "NT"},
                {"type": "LM", "hashcat_mode": 3000, "john_format": "LM"}
            ]
        
        result = {
            "hash": hash_value,
            "length": len(hash_value),
            "possible_types": possible_types if possible_types else [{"type": "Unknown"}],
            "cracking_tips": []
        }
        
        if possible_types:
            mode = possible_types[0].get("hashcat_mode")
            fmt = possible_types[0].get("john_format")
            if mode and mode != "Unknown":
                result["cracking_tips"].append(f"hashcat -m {mode} hash.txt wordlist.txt")
            if fmt and fmt != "Unknown":
                result["cracking_tips"].append(f"john --format={fmt} hash.txt")
        
        return json.dumps(result, indent=2)
        
    except Exception as e:
        logger.error(f"Hash identification error: {e}")
        return f"Error: {str(e)}"


@tool
def hash_string(text: str, algorithm: str = "md5") -> str:
    """
    Generate hash of a string using various algorithms.
    
    Args:
        text: Text to hash
        algorithm: Hashing algorithm - md5, sha1, sha256, sha512
        
    Returns:
        Hash value
        
    Examples:
        hash_string("password123", "md5")
        hash_string("admin", "sha256")
    """
    try:
        algorithm = algorithm.lower().strip()
        
        algorithms = {
            "md5": hashlib.md5,
            "sha1": hashlib.sha1,
            "sha256": hashlib.sha256,
            "sha512": hashlib.sha512,
            "sha384": hashlib.sha384,
            "blake2b": hashlib.blake2b,
            "blake2s": hashlib.blake2s,
        }
        
        if algorithm not in algorithms:
            return json.dumps({
                "error": f"Unknown algorithm: {algorithm}",
                "available": list(algorithms.keys())
            }, indent=2)
        
        hash_obj = algorithms[algorithm](text.encode())
        
        result = {
            "input": text,
            "algorithm": algorithm.upper(),
            "hash": hash_obj.hexdigest(),
            "base64": __import__('base64').b64encode(hash_obj.digest()).decode()
        }
        
        return json.dumps(result, indent=2)
        
    except Exception as e:
        logger.error(f"Hashing error: {e}")
        return f"Error: {str(e)}"


@tool
def generate_wordlist_command(target_info: str) -> str:
    """
    Generate custom wordlist creation commands based on target info.
    
    Args:
        target_info: Information about the target (company name, location, etc.)
        
    Returns:
        Commands to generate custom wordlists
        
    Examples:
        generate_wordlist_command("Acme Corp, California, founded 2010")
    """
    try:
        # Extract keywords
        words = target_info.replace(',', ' ').split()
        base_words = [w.strip().lower() for w in words if len(w) > 2]
        
        # Generate variations
        variations = []
        for word in base_words[:5]:  # Limit to 5 base words
            variations.append(word)
            variations.append(word.capitalize())
            variations.append(word.upper())
            variations.append(word + "123")
            variations.append(word + "2024")
            variations.append(word + "!")
        
        result = {
            "base_words": base_words,
            "sample_variations": variations[:20],
            "commands": {
                "cewl": f"cewl -d 2 -m 5 https://target.com -w wordlist.txt",
                "crunch": f"crunch 6 8 -t ,,,@@@ -o wordlist.txt",
                "cupp": "cupp -i  # Interactive personal wordlist",
                "john_rules": f"john --wordlist=wordlist.txt --rules --stdout > expanded.txt"
            },
            "common_wordlists": [
                "/usr/share/wordlists/rockyou.txt",
                "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt",
                "/usr/share/wordlists/dirb/common.txt"
            ]
        }
        
        return json.dumps(result, indent=2)
        
    except Exception as e:
        logger.error(f"Wordlist command error: {e}")
        return f"Error: {str(e)}"
