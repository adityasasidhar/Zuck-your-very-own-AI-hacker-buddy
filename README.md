# Cybersecurity AI Assistant

A Python-based cybersecurity assistant powered by Google's Gemini AI that helps users with cybersecurity tasks and system administration on Linux-based operating systems.

## Description

This project creates an AI assistant named "Zuck" that can help with cybersecurity-related questions and tasks. The assistant can propose terminal commands for the user to execute, with built-in safety measures to prevent dangerous operations.

## Features

- AI-powered cybersecurity assistance
- Terminal command execution with safety checks
- Support for various cybersecurity tools:
  - NMAP
  - WHOIS
  - TCPDUMP
  - TSHARK
  - NETCAT
  - DNSUTILS
  - AIRCRACK-NG

## Installation

1. Clone this repository:
   ```
   git clone <repository-url>
   cd <repository-directory>
   ```

2. Install the required dependencies:
   ```
   pip install google-generativeai
   ```

3. Create an `apikey.txt` file with your Google Gemini API key:
   ```
   echo "your-api-key-here" > apikey.txt
   ```

## Usage

### Basic Usage

Run the main script:
```
python main.py
```

### Advanced Usage

For more features, use the working script:
```
python working.py
```

Or use the dual execution mode:
```
python dual.py
```

## Files

- `main.py`: Simple implementation of the AI assistant
- `working.py`: Enhanced version with command extraction and safety checks
- `dual.py`: Implementation with command safety verification and execution
- `apikey.txt`: Stores your Google Gemini API key

## Safety Features

The assistant includes several safety measures:
- Command blocklist to prevent dangerous operations
- Pattern matching for suspicious commands
- Human oversight requirement for all proposed commands
- Informative warnings about commands requiring elevated privileges

## Dependencies

- Google Generative AI Python SDK
- Python 3.6+

## License

[Specify your license here]

## Disclaimer

This tool is for educational and legitimate cybersecurity purposes only. Always review commands before execution and use responsibly.