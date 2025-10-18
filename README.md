# Zuck - AI Cybersecurity Agent

A cybersecurity-focused AI assistant powered by Google's Gemini 2.0 Flash model. This project provides an interactive terminal interface for cybersecurity and system administration tasks on Linux systems.

## Features

- **AI-Powered Command Generation**: Suggests terminal commands for cybersecurity tasks
- **Safety Measures**: Includes command blocklisting and validation to prevent destructive operations
- **Specialized Tools Access**: Pre-configured to work with common cybersecurity tools
- **Interactive Interface**: Continuous conversation flow with command execution feedback

## Prerequisites

- Python 3.7 or higher
- Google API key for Gemini (https://ai.google.dev/)
- Linux-based operating system ( will work in macos and windows too with adjustment)
- The following cybersecurity tools (for full functionality), you could add more if you like:
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
   git clone https://github.com/adityasasidhar/Zuck-your-very-own-AI-hacker-buddy.git
   cd Zuck-your-very-own-AI-hacker-buddy
   ```

2. Install required Python packages:
   ```
   pip install -r requirements.txt
   ```

3. Create an API key file:
   ```
   echo "YOUR_GOOGLE_API_KEY" > apikey.txt
   ```
   Replace `YOUR_GOOGLE_API_KEY` with your actual Google Gemini API key.

## Setup

### Getting a Google Gemini API Key

1. Visit the [Google AI Studio](https://ai.google.dev/)
2. Sign in with your Google account
3. Navigate to the API section
4. Create a new API key
5. Copy the key and save it to `apikey.txt` in the project root directory

### Installing Required Tools (Ubuntu/Debian/Pop!_OS)

```
sudo apt update
sudo apt install nmap whois tcpdump tshark netcat dnsutils aircrack-ng
```

## Usage

### Main Cybersecurity Assistant

Run the main implementation for the full cybersecurity assistant experience:

```
python main.py
```

This will start Zuck, the cybersecurity assistant. You can ask it questions related to cybersecurity and system administration, and it will suggest appropriate terminal commands.

## How It Works

1. The assistant receives your query about a cybersecurity or system administration task
2. It generates an appropriate terminal command to address your query
3. The command is displayed for your approval
4. Upon your confirmation, the command is executed
5. The output is fed back to the assistant for further analysis
6. The conversation continues with additional commands as needed

# Run the agent
python zuck_agent.py

# View analytics for latest session
python analytics.py --latest

# List all sessions
python analytics.py --list

# Generate report for specific session
python analytics.py --report 20241018_143022

# Compare multiple sessions
python analytics.py --compare 20241018_143022 20241018_150134

## Safety Features

- Command blocklist to prevent destructive operations
- Human oversight requirement for all commands
- Informative warnings about commands requiring elevated privileges
- Preference for non-destructive alternatives when available

## Limitations

- Requires internet connection for API access
- Some suggested commands may require sudo privileges
- Limited to the pre-installed cybersecurity tools
- Designed primarily for Linux environments

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Google Gemini API for providing the AI capabilities
- Contributors and maintainers of the cybersecurity tools used in this project
