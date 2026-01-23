# Zuck - Your Very Own AI Hacker Buddy

**Zuck** is an elite AI-powered cybersecurity assistant designed for penetration testing, security research, and offensive security operations. Built on LangChain and powered by multiple LLM providers, Zuck provides a sophisticated command-line interface with persistent shell access, specialized security tools, and intelligent automation capabilities.

## Features

### Core Capabilities

- **Persistent Shell Access**: Full PTY (pseudo-terminal) session with state preservation across commands
- **Multi-Provider LLM Support**: Compatible with Google Gemini, OpenAI, Anthropic Claude, Groq, and Ollama
- **33+ Specialized Tools**: Comprehensive toolkit for reconnaissance, exploitation, defense, and analysis
- **Interactive REPL**: Rich terminal interface with syntax highlighting and autocomplete
- **Session Management**: Multiple isolated shell sessions with background process support
- **Intelligent Planning**: Multi-step task planning and execution tracking

### Tool Categories

#### 1. Shell Access (14 tools)
- Execute commands with persistent state
- Run background processes for long-running scans
- Interactive program support (Python REPL, vim, htop)
- Session isolation and management
- Command history tracking

#### 2. OSINT & Reconnaissance (4 tools)
- **Shodan Integration**: Host lookups and vulnerability searches
- **Social Analysis**: Username enumeration and email OSINT
- Network reconnaissance and footprinting

#### 3. Offensive Security (4 tools)
- **CVE Lookup**: Vulnerability database queries
- **Exploit-DB Integration**: Search and retrieve exploit code
- **SQL Injection**: Payload generation and testing
- Exploit information and PoC retrieval

#### 4. Defensive Security (3 tools)
- **IOC Extraction**: Identify indicators of compromise from text and files
- **VirusTotal Integration**: File hash analysis and threat intelligence
- Malware analysis support

#### 5. Utilities (8 tools)
- HTTP request builder
- Python REPL for scripting
- Wikipedia research
- Task planning and tracking
- Wait timers for automation

## Installation

### Prerequisites

- Python 3.12 or higher
- Linux operating system (recommended)
- API keys for your chosen LLM provider(s)

### Setup

1. **Clone the repository**
```bash
git clone https://github.com/adityasasidhar/Zuck-your-very-own-AI-hacker-buddy.git
cd Zuck-your-very-own-AI-hacker-buddy
```

2. **Install dependencies**
```bash
# Using uv (recommended)
uv sync

# Or using pip
pip install -e .
```

3. **Configure environment variables**

Create a `.env` file in the project root:

```env
# LLM Provider Configuration
PROVIDER=google  # Options: google, openai, anthropic, groq, ollama
MODEL_NAME=gemini-2.5-flash
TEMPERATURE=0.7

# API Keys (add the ones you need)
GOOGLE_API_KEY=your_google_api_key
OPENAI_API_KEY=your_openai_api_key
ANTHROPIC_API_KEY=your_anthropic_api_key
GROQ_API_KEY=your_groq_api_key

# Optional: Security Tool API Keys
SHODAN_API_KEY=your_shodan_key
VIRUSTOTAL_API_KEY=your_virustotal_key

# Agent Configuration
MAX_COMMANDS=50
LOG_DIRECTORY=./logs
```

## Usage

### Basic Usage

Start Zuck with default settings from your `.env` file:

```bash
python -m zuck
```

### Advanced Usage

Override configuration with command-line arguments:

```bash
# Use a specific provider and model
python -m zuck --provider google --model gemini-2.5-flash

# Adjust temperature for more creative responses
python -m zuck --temp 0.9

# Set maximum commands per session
python -m zuck --max-commands 100
```

### Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--provider` | LLM provider (google, openai, anthropic, groq, ollama) | From `.env` |
| `--model` | Model name | Provider-specific default |
| `--temp` | Temperature (0.0-2.0) | 0.7 |
| `--max-commands` | Maximum commands per session | 50 |

### Interactive Commands

Once inside the Zuck REPL:

- `help` - Display help information
- `tools` - List all available tools
- `clear` - Clear the terminal screen
- `quit`, `exit`, `bye`, `q` - Exit the session
- `/` - Slash commands for special operations

## Example Workflows

### Network Reconnaissance

```
> Scan target.com for open ports and services

Zuck will:
1. Run nmap scan: nmap -sV -p- target.com
2. Perform Shodan lookup for additional intel
3. Execute DNS enumeration: dig target.com ANY
4. Analyze and summarize findings
```

### Vulnerability Research

```
> Find exploits for Apache 2.4.49

Zuck will:
1. Look up CVE-2021-41773
2. Search Exploit-DB for proof-of-concept code
3. Provide exploitation guidance
4. Suggest mitigation strategies
```

### Log Analysis

```
> Analyze /var/log/auth.log for suspicious activity

Zuck will:
1. Navigate to log directory
2. Extract failed login attempts
3. Identify IOCs (IP addresses, usernames)
4. Provide security recommendations
```

## Architecture

### Project Structure

```
zuck/
├── cli/              # Command-line interface and REPL
│   ├── main.py       # Entry point and argument parsing
│   ├── repl.py       # Interactive loop
│   ├── display.py    # Rich terminal output
│   └── slash_commands.py
├── core/             # Core agent logic
│   ├── agent.py      # Main ZuckAgent orchestrator
│   ├── config.py     # Configuration management
│   ├── models.py     # Data models
│   └── session.py    # Session state tracking
├── llm/              # LLM provider abstraction
│   └── factory.py    # Multi-provider factory
├── tools/            # Tool implementations
│   ├── exploit_db.py
│   ├── shodan.py
│   ├── virustotal.py
│   └── ...
├── shell/            # Shell session management
│   ├── manager.py
│   ├── session.py
│   └── tools.py
├── security/         # Security validation
│   ├── patterns.py
│   └── validator.py
└── utils/            # Utilities and logging
    ├── logging.py
    ├── system.py
    └── tracking.py
```

### Technology Stack

- **LangChain**: Agent framework and tool orchestration
- **Deep Agents**: Advanced ReAct loop implementation
- **Rich**: Terminal UI and formatting
- **Multiple LLM Providers**: Flexible model selection
- **Python 3.12+**: Modern Python features

## Security Considerations

### Authorization Context

Zuck is designed for **authorized penetration testing and security research only**. The agent operates under the assumption that:

- All activities are pre-approved by system owners
- Testing occurs in isolated, controlled environments
- Operations are legal and within scope of engagement
- Users have proper authorization and credentials

### Safety Features

- **Input Validation**: Command sanitization and pattern matching
- **Session Isolation**: Separate environments for different tasks
- **Logging**: Comprehensive audit trail of all operations
- **API Key Protection**: Environment-based credential management

### Responsible Use

**WARNING**: Unauthorized access to computer systems is illegal. Always:

- Obtain written permission before testing
- Operate within defined scope boundaries
- Follow responsible disclosure practices
- Comply with local laws and regulations

## Development

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=zuck
```

### Code Style

The project follows PEP 8 guidelines. Format code with:

```bash
black zuck/
isort zuck/
```

### Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Submit a pull request

## Troubleshooting

### Common Issues

**Issue**: `ModuleNotFoundError` when running Zuck
- **Solution**: Ensure you've installed dependencies with `uv sync` or `pip install -e .`

**Issue**: API authentication errors
- **Solution**: Verify your API keys in `.env` are correct and have proper permissions

**Issue**: Shell commands not persisting state
- **Solution**: Use `shell_run()` for sequential commands or chain with `&&`

**Issue**: Background processes not responding
- **Solution**: Check process status with `shell_get_background_output(bg_id)`

## Roadmap

- [ ] Web interface for remote access
- [ ] Plugin system for custom tools
- [ ] Automated report generation
- [ ] Multi-target campaign management
- [ ] Integration with Metasploit Framework
- [ ] Docker containerization
- [ ] Cloud deployment options

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with [LangChain](https://github.com/langchain-ai/langchain)
- Powered by [Deep Agents](https://github.com/deepagents/deepagents)
- Terminal UI by [Rich](https://github.com/Textualize/rich)
- Inspired by the cybersecurity community

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. The developers assume no liability for misuse or damage caused by this program. Users are responsible for complying with all applicable laws and regulations.

---

**Built with ❤️ for the security research community**
