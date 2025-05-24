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
   git clone <repository-url>
   cd <repository-directory>
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

### Simple Chat Implementation

For a basic demonstration of the Gemini chat functionality:

```
python "chat_based_implementation.py"
```

This runs a simplified version that demonstrates basic chat interaction without the cybersecurity features.

## How It Works

1. The assistant receives your query about a cybersecurity or system administration task
2. It generates an appropriate terminal command to address your query
3. The command is displayed for your approval
4. Upon your confirmation, the command is executed
5. The output is fed back to the assistant for further analysis
6. The conversation continues with additional commands as needed

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

[Specify your license information here]

## Acknowledgments

- Google Gemini API for providing the AI capabilities
- Contributors and maintainers of the cybersecurity tools used in this project