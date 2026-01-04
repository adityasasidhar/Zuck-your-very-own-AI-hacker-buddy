# Zuck - AI Cybersecurity Agent

A modular, cybersecurity-focused AI assistant powered by **LangChain** with support for multiple LLM providers (Google Gemini, OpenAI, Anthropic Claude, Ollama). This project provides an interactive terminal interface for cybersecurity and system administration tasks on Linux systems.

## Features

- **Multi-Provider LLM Support**: Easily switch between Google Gemini, OpenAI, Anthropic, or local Ollama models
- **AI-Powered Command Generation**: Suggests terminal commands for cybersecurity tasks
- **Modular Architecture**: Clean package structure with separation of concerns
- **10 Built-in Security Tools**: Calculator, VirusTotal, DNS, WHOIS, HTTP, file reader, and more
- **Safety Measures**: Includes command blocklisting and validation to prevent destructive operations
- **Interactive Interface**: Continuous conversation flow with command execution feedback
- **Token Tracking**: Monitor API usage and costs across all providers
- **Comprehensive Logging**: Detailed session logs and analytics

## Project Structure

```
zuck/
├── core/           # Agent orchestration, config, models
├── llm/            # LLM provider abstraction (Google, OpenAI, Anthropic, Ollama)
├── tools/          # 10 individual security tools
├── security/       # Command validation and security patterns
├── execution/      # Shell command execution
├── utils/          # Logging, tracking, system info
└── cli/            # Interactive REPL interface
```

## Prerequisites

- Python 3.8 or higher
- Google API key for Gemini (<https://ai.google.dev/>) (or other provider API keys)
- Linux-based operating system (will work in macOS and Windows with adjustment)
- The following cybersecurity tools (for full functionality):
  - NMAP
  - WHOIS
  - TCPDUMP
  - TSHARK
  - NETCAT
  - DNSUTILS
  - AIRCRACK-NG

## Installation

1. Clone this repository:

   ```bash
   git clone https://github.com/adityasasidhar/Zuck-your-very-own-AI-hacker-buddy.git
   cd Zuck-your-very-own-AI-hacker-buddy
   ```

2. Create and activate a virtual environment:

   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. Install required Python packages:

   ```bash
   pip install -r requirements.txt
   ```

4. Create an API key file:

   ```bash
   echo "YOUR_GOOGLE_API_KEY" > apikey.txt
   ```

   Replace `YOUR_GOOGLE_API_KEY` with your actual Google Gemini API key.

## Quick Start

### Running the Agent

```bash
# Standard way
python main.py

# As a Python module
python -m zuck

# With custom options
python -m zuck --provider google --model gemini-2.5-flash --temp 0.3
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--provider` | LLM provider (google, openai, anthropic, ollama) | google |
| `--model` | Model name | gemini-2.5-flash |
| `--temp` | Temperature (0.0-2.0) | 0.3 |
| `--max-commands` | Max commands per session | 50 |

## Using as a Library

```python
from zuck import ZuckAgent, AgentConfig

# Create configuration
config = AgentConfig(
    provider="google",
    model_name="gemini-2.5-flash",
    temperature=0.3
)

# Initialize and run
agent = ZuckAgent(config)
agent.run()
```

### Using Individual Components

```python
# Use the LLM provider directly
from zuck.llm import create_provider
from zuck.core.config import AgentConfig

config = AgentConfig(provider="google")
provider = create_provider(config)

# Use tools
from zuck.tools import get_all_tools, get_tool_by_name

tools = get_all_tools()
calculator = get_tool_by_name("calculator")
result = calculator.invoke({"expression": "192.168.1.0/24 size"})
```

## LLM Provider Configuration

### Google Gemini (Default)

```bash
echo "YOUR_GOOGLE_API_KEY" > apikey.txt
python main.py
```

### OpenAI

```python
config = AgentConfig(
    provider="openai",
    model_name="gpt-4",
    openai_api_key="sk-..."  # or set OPENAI_API_KEY env var
)
```

### Anthropic Claude

```python
config = AgentConfig(
    provider="anthropic",
    model_name="claude-3-5-sonnet-20241022",
    anthropic_api_key="sk-ant-..."  # or set ANTHROPIC_API_KEY env var
)
```

### Ollama (Local)

```python
config = AgentConfig(
    provider="ollama",
    model_name="llama3.1"  # No API key needed!
)
```

## Built-in Tools

| Tool | Description |
|------|-------------|
| `calculator` | Network calculations (subnet size, IP ranges, hex/decimal) |
| `virustotal_lookup` | Check file hashes, URLs, domains, IPs for malware |
| `datetime_tool` | Parse timestamps, analyze log times |
| `memory_store` | Store and retrieve findings during session |
| `read_file` | Read configuration files and logs safely |
| `http_request` | Make HTTP requests to test APIs |
| `dns_lookup` | Query DNS records (A, MX, TXT, NS, etc.) |
| `whois_lookup` | Get domain registration information |
| `python_repl` | Execute Python code for data analysis |
| `wikipedia_search` | Look up security concepts and protocols |

## How It Works

1. The assistant receives your query about a cybersecurity or system administration task
2. It generates an appropriate terminal command or uses a built-in tool
3. Commands are displayed for your approval
4. Upon confirmation, the command is executed
5. The output is fed back to the assistant for further analysis
6. The conversation continues with additional commands as needed

## Analytics

### View analytics for latest session

```bash
python analytics.py --latest
```

### List all sessions

```bash
python analytics.py --list
```

### Generate report for specific session

```bash
python analytics.py --report 20241018_143022
```

### Compare multiple sessions

```bash
python analytics.py --compare 20241018_143022 20241018_150134
```

## Safety Features

- **Critical Command Blocking**: Prevents destructive operations (rm -rf /, mkfs, dd to devices)
- **High-Risk Warnings**: Extra confirmation for shutdown, reboot, firewall changes
- **Human Oversight**: All commands require user approval before execution
- **Secure File Access**: Blocks reading sensitive files like /etc/shadow

## Adding New Tools

Create a new file in `zuck/tools/`:

```python
# zuck/tools/my_tool.py
from langchain.tools import tool

@tool
def my_tool(input: str) -> str:
    """Description of what your tool does."""
    # Tool implementation
    return result
```

Then add it to `zuck/tools/registry.py`.

## Adding New LLM Providers

Create a new file in `zuck/llm/`:

```python
# zuck/llm/my_provider.py
from zuck.llm.base import BaseLLMProvider, LLMResponse

class MyProvider(BaseLLMProvider):
    def invoke(self, messages):
        # Implementation
        return LLMResponse(content=..., tool_calls=...)
    
    def bind_tools(self, tools):
        # Implementation
        pass
```

Then add it to `zuck/llm/factory.py`.

## Limitations

- Requires internet connection for API access (except Ollama)
- Some suggested commands may require sudo privileges
- Limited to the pre-installed cybersecurity tools
- Designed primarily for Linux environments

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
