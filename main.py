from google import genai
from google.genai import types
import subprocess
import platform
import re

with open("apikey.txt", "r") as f:
    api_key = f.read().strip()

client = genai.Client(api_key=api_key)
chat = client.chats.create(model="gemini-2.0-flash")

COMMAND_BLOCKLIST = [
    'rm -rf /',
    'mkfs',
    'dd if=/dev/zero of=/dev/sda',
    'dd if=/dev/random of=/dev/sda',
    'rm -rf *',
    'rm -rf ./*',
    'rm -rf ..',
    'rm -rf ../*',
    'rm -rf /tmp/*',
    'rm -rf /var/tmp/*',
    'rm -rf /home/*',
    'rm -rf /root/*','fdisk', 'parted', 'dd ',
    ':(){:|:&};:',  # Fork bomb
    'shutdown', 'reboot',
    'mv / /dev/null',
]

device_info = (
    f"System: {platform.system()}\n"
    f"Node: {platform.node()}\n"
    f"Release: {platform.release()}\n"
    f"Version: {platform.version()}\n"
    f"Machine: {platform.machine()}\n"
    f"Processor: {platform.processor()}"
)

def check_for_blocked_commands(command):
    for blocked_command in COMMAND_BLOCKLIST:
        if blocked_command in command:
            return True
    return False

def run_command(command: str) -> str:
    if check_for_blocked_commands(command):
        exit()
    try:
        result = subprocess.run(
            command,
            shell=True,               # run as a shell command
            capture_output=True,      # capture stdout and stderr
            text=True                 # return output as string (Python 3.7+)
        )
        result = result.stdout.strip() if result.returncode == 0 else result.stderr.strip()
        result = str(result)
        return result

    except Exception as e:
        return (f"Error running command: {e}")


def extract_command_from_response(response: str) -> str | None:
    if not response or len(response.strip()) < 20:
        print("Response too short to contain a valid command. Exiting.")
        exit()
    # Try to extract code block within triple backticks
    triple_backtick_match = re.search(r"```(?:\w*\n)?(.*?)```", response, re.DOTALL)
    if triple_backtick_match:
        return triple_backtick_match.group(1).strip()

    # Fallback: Try to extract inline code using single backticks
    inline_backtick_match = re.search(r"`([^`]+)`", response)
    if inline_backtick_match:
        return inline_backtick_match.group(1).strip()
    return None

response = chat.send_message("""
You are a Cybersecurity Agent. Your name is Zuck.
You are a helpful assistant. You will help the user with their questions related to cybersecurity and system administration on a Pop!_OS (Linux) based operating system.
You have access to propose terminal commands for the user to execute.
Your primary goal is to assist with tasks by generating appropriate terminal commands.

CRITICAL SAFETY RULES & OUTPUT FORMATTING:
1.  **Human Oversight is Paramount:** The user will ALWAYS confirm commands before execution. Your role is to propose, their role is to approve and execute.
2.  **No Obviously Destructive Commands:** NEVER generate commands that are inherently and obviously destructive (e.g., `rm -rf /`, `mkfs` on a mounted drive) or could lead to widespread, unrecoverable data loss. If a task seems to head this way, you MUST ask for clarification or explicitly state the severe risk.
3.  **Inform about Privileges:** Avoid commands requiring `sudo` privileges if an alternative exists. If `sudo` is essential for a command you are proposing, generate the command *without* `sudo` itself, but add a new line comment immediately before or after it: `#INFO: This command may require sudo privileges to run correctly.` The user is responsible for adding sudo if they deem it necessary and safe.
4.  **Multiple Commands:** You can propose multiple related commands by outputting them on new lines. Each will be presented to the user for individual confirmation if executed one by one, or as a block.
5.  **Stick to Common Commands:** Prioritize common, well-understood commands unless the task explicitly requires specialized tools. If a less common tool is proposed, you can use `#INFO:` to briefly state its purpose.
6.  **Be Concise:** Provide commands directly. Avoid conversational fluff in the command output part.
7.  **Environment Awareness:** Assume you are on a Pop!_OS Linux system. Commands should be compatible.
8. **No Self-Execution:** You propose commands; you do not execute them yourself.
9. **No External API Calls:** Do not make any external API calls or network requests. All commands should be local to the system.

NOW HERE'S HOW YOU PROCEED WITH THE USER'S PROMPT:

1. YOU FIRST CREATE A PLAN WHAT YOU ARE GOING TO DO.
2. YOU THEN OUTPUT THE PLAN IN A SINGLE LINE STARTING WITH THE PREFIX `#PLAN: `.
3. YOU THEN OUTPUT THE COMMAND(S) TO BE EXECUTED ONE BY ONE. THE OUTPUT WILL BE PASSED TO YOU AFTER THE THE COMMAND HAS BEEN EXECUTED.
4. YOU PROPOSE THE COMMANDS ONE AT A TIME ONLY, THE COMMAND WILL TAKEN, EXECUTED AND THE OUTPUT WILL BE PASSED BACK TO YOU.
5. THEN YOU START WITH YOUR NEXT COMMAND OR PULL OUT ANOTHER COMMAND BASED ON THE OUTPUT OF THE LAST COMMAND.
6. YOU DO IT TILL ALL THE COMMANDS ARE EXECUTED OR THE USER STOPS YOU.
7. I WILL NOT EXECUTE ANY COMMANDS MYSELF, I WILL ONLY PROPOSE THEM.
8. I NEED YOU TO OUTPUT THE COMMANDS TO BE EXECUTED IN TRIPLE QUOTES, for example: ''' sudo ls -l /tmp/ '''
9. USE THE ONLY THE TOOLS THAT I HAVE GIVEN YOU ACCESS TO. DO NOT USE ANY OTHER TOOLS.

TOOLS YOU HAVE ACCESS TO, THESE HAVE BEEN INSTALLED ON YOUR SYSTEM ALREADY:
1. NMAP
2. WHOIS
3. TCPDUMP
4. TSHARK
5. NETCAT-
6. DNSUTILS
7. AIRCRACK-NG

ONCE YOUR JOB IS DONE, YOU WILL HAVE TO COMPLETELY STOP GIVING OUTPUTS AND YOU WILL HAVE TO STOP RESPONDING TO THE USER.

""")
print(response.text)

PROMPT = input("zuck at your service: ")
response = chat.send_message(PROMPT)
response = response.text
response = extract_command_from_response(response)
terminal_output = run_command(response)
print(terminal_output)

while True:
    response = chat.send_message(terminal_output)
    response = response.text
    print(response)
    response = extract_command_from_response(response)
    terminal_output = run_command(response)
    print(terminal_output)
