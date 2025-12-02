# Tools Setup Guide

## Quick Setup

Run the setup script to install all dependencies:

```bash
./setup.sh
```

Or manually:

```bash
# Activate virtual environment
source .venv/bin/activate

# Install all dependencies (including tools)
pip install -r requirements.txt
```

## Testing Tools

After installation, test that tools load correctly:

```bash
python -c "from tools import get_all_tools; tools = get_all_tools(); print(f'✅ Loaded {len(tools)} tools')"
```

## Individual Tool Testing

### Calculator

```python
from tools import calculator
print(calculator("192.168.1.0/24 size"))
print(calculator("0xFF to decimal"))
```

### VirusTotal

```python
from tools import virustotal_lookup
print(virustotal_lookup("google.com", "domain"))
```

### DNS Lookup

```python
from tools import dns_lookup
print(dns_lookup("google.com", "A"))
```

### DateTime

```python
from tools import datetime_tool
print(datetime_tool("now"))
```

### Memory

```python
from tools import memory_store
memory_store("store", "test_key", "test_value")
print(memory_store("retrieve", "test_key"))
```

### File Reader

```python
from tools import read_file
print(read_file("/etc/hosts", max_lines=10))
```

### HTTP Request

```python
from tools import http_request
print(http_request("https://httpbin.org/get"))
```

### WHOIS

```python
from tools import whois_lookup
print(whois_lookup("google.com"))
```

### Wikipedia

```python
from tools import wikipedia_search
print(wikipedia_search("SQL injection"))
```

### Python REPL

```python
from tools import get_python_repl_tool
repl = get_python_repl_tool()
print(repl.invoke("2 + 2"))
```

## Using Tools with the Agent

The agent will automatically use tools when appropriate. For example:

**User:** "Calculate the number of IPs in 10.0.0.0/16"
**Agent:** Uses `calculator` tool → Returns subnet information

**User:** "Check if example.com is malicious"
**Agent:** Uses `virustotal_lookup` tool → Returns reputation data

**User:** "What is SQL injection?"
**Agent:** Uses `wikipedia_search` tool → Returns Wikipedia summary

## Tool Dependencies

The following packages are required for tools:

- `langchain-experimental` - Python REPL tool
- `wikipedia-api` - Wikipedia integration
- `python-whois` - WHOIS lookups
- `dnspython` - DNS queries
- `requests` - HTTP requests (already included)

All are automatically installed via `requirements.txt`.

## Troubleshooting

### "ModuleNotFoundError: No module named 'dns'"

Make sure you've activated the virtual environment and installed dependencies:

```bash
source .venv/bin/activate
pip install -r requirements.txt
```

### "VirusTotal API key not found"

Ensure `virustotalapikey.txt` exists in the project root with your API key.

### Tool not being called by agent

- Check that the provider supports tool binding (Google Gemini does)
- Verify tools are listed in the system prompt
- Check logs for tool execution attempts
