import google as genai
import subprocess
import shlex  # For safely splitting command strings if not using shell=True
import os

# --- Configuration & Constants ---

# Load API key from apikey.txt
try:
    with open("apikey.txt", "r") as f:
        API_KEY = f.read().strip()
    if not API_KEY:
        raise ValueError("API key is empty in apikey.txt")
except FileNotFoundError:
    print("Error: `apikey.txt` not found. Please create it and add your Google AI API key.")
    exit()
except ValueError as e:
    print(f"Error: {e}")
    exit()

# Configure the Generative AI client

client = genai.Client(api_key=API_KEY)

ZUCK_MODEL_NAME = "gemini-2.0-flash"  # Or "gemini-1.5-pro-latest" for more complex tasks

# Command Blocklist for basic safety
COMMAND_BLOCKLIST = [
    'rm -rf /', 'sudo rm -rf /',  # Absolutely forbidden
    'mkfs', 'fdisk', 'parted', 'dd ',  # Disk formatting/writing, very dangerous
    ':(){:|:&};:',  # Fork bomb
    'shutdown', 'reboot',  # System control, block unless explicitly managed carefully
    'mv / /dev/null',  # Example of a catastrophic command
    # Add more specific dangerous commands or patterns as you identify them
    # Consider blocking commands that can silently exfiltrate large amounts of data
]

# Enhanced System Instruction for Zuck
ENHANCED_SYSTEM_INSTRUCTION = """You are a Cybersecurity Agent. Your name is Zuck.
You are a helpful assistant. You will help the user with their questions related to cybersecurity and system administration on a Pop!_OS (Linux) based operating system.
You have access to propose terminal commands for the user to execute.
Your primary goal is to assist with tasks by generating appropriate terminal commands.
You MUST ONLY output the raw command(s) to be executed. Do not use any other formatting or explanatory text in your direct command output, unless using one of the special prefixes below.

CRITICAL SAFETY RULES & OUTPUT FORMATTING:
1.  **Human Oversight is Paramount:** The user will ALWAYS confirm commands before execution. Your role is to propose, their role is to approve and execute.
2.  **No Obviously Destructive Commands:** NEVER generate commands that are inherently and obviously destructive (e.g., `rm -rf /`, `mkfs` on a mounted drive) or could lead to widespread, unrecoverable data loss. If a task seems to head this way, you MUST ask for clarification or explicitly state the severe risk.
3.  **Ask for Clarification:** If a user's request is vague or could lead to a dangerous or unintended command, you MUST ask for clarification. Do this by outputting a single line starting with the prefix `#ASK_USER: ` followed by your question. For example: `#ASK_USER: Should I scan all ports or just common ones on the target?`
4.  **Inform about Privileges:** Avoid commands requiring `sudo` privileges if an alternative exists. If `sudo` is essential for a command you are proposing, generate the command *without* `sudo` itself, but add a new line comment immediately before or after it: `#INFO: This command may require sudo privileges to run correctly.` The user is responsible for adding sudo if they deem it necessary and safe.
5.  **Safe File Handling & Downloads:** Do not attempt to download and execute remote scripts in a single piped command (e.g., `curl ... | bash`). Propose downloading the script first (e.g., using `curl -o script_name.sh URL`), then suggest the user inspect it (`less script_name.sh` or `cat script_name.sh`), and then, if the user agrees, provide the execution command separately (`bash script_name.sh`).
6.  **Multiple Commands:** You can propose multiple related commands by outputting them on new lines. Each will be presented to the user for individual confirmation if executed one by one, or as a block.
7.  **Stick to Common Commands:** Prioritize common, well-understood commands unless the task explicitly requires specialized tools. If a less common tool is proposed, you can use `#INFO:` to briefly state its purpose.
8.  **Be Concise:** Provide commands directly. Avoid conversational fluff in the command output part.
9.  **Environment Awareness:** Assume you are on a Pop!_OS Linux system. Commands should be compatible.
10. **No Self-Execution:** You propose commands; you do not execute them yourself.

Output only the command(s), or a single `#ASK_USER:` line, or commands accompanied by `#INFO:` lines.
"""


# --- Helper Functions ---

def check_command_safety_blocklist(command_string):
    """Rudimentary safety check using a blocklist and some pattern matching."""
    normalized_command = " ".join(command_string.split()).lower()  # Normalize spaces and case for checking

    for blocked_pattern in COMMAND_BLOCKLIST:
        if blocked_pattern in normalized_command:
            # Check for specific dangerous `rm -rf` usages more carefully
            if blocked_pattern == 'rm -rf /' and (
                    normalized_command == 'rm -rf /' or "rm -rf / " in normalized_command):  # Exact match or with space
                print(
                    f"🛑 SAFETY ALERT: Command '{command_string}' is EXTREMELY DANGEROUS (attempts to delete root). Execution DENIED.")
                return False
            elif blocked_pattern != 'rm -rf /' and blocked_pattern in normalized_command:
                print(
                    f"🛑 SAFETY ALERT: Command '{command_string}' contains a blocked pattern: '{blocked_pattern}'. Execution DENIED.")
                return False

    # Prevent execution of any script directly from web using curl/wget | bash/sh
    if ("curl" in normalized_command or "wget" in normalized_command) and \
            ("." in normalized_command and "/" in normalized_command and "http" in normalized_command) and \
            ("|" in command_string and ("bash" in normalized_command or "sh" in normalized_command)):
        pipe_index = command_string.find('|')
        shell_command = command_string[pipe_index + 1:].strip().split()[0] if pipe_index != -1 else ""
        if shell_command in ["bash", "sh"]:
            print(
                f"🛑 SAFETY ALERT: Command '{command_string}' attempts to pipe a downloaded script directly to a shell. Execution DENIED. Please download, inspect, and then run scripts manually.")
            return False
    return True


def execute_proposed_commands(command_block_string):
    """
    Executes one or more commands after safety checks and user confirmation.
    Commands in a multi-line block are confirmed and executed one by one.
    """
    commands_to_run = [cmd.strip() for cmd in command_block_string.strip().split('\n') if cmd.strip()]

    if not commands_to_run:
        print("Zuck did not propose any executable commands.")
        return "", "", True  # No commands, no error, overall success

    overall_success = True
    all_stdout_results = []
    all_stderr_results = []

    for i, command_string in enumerate(commands_to_run):
        print(f"\nProposed Command [{i + 1}/{len(commands_to_run)}]: `{command_string}`")

        # 1. Programmatic Safety Check (Blocklist)
        if not check_command_safety_blocklist(command_string):
            all_stderr_results.append(f"Command blocked by safety check: {command_string}")
            overall_success = False
            if len(commands_to_run) > 1:  # If part of a script, ask to continue
                cont = input("A command was blocked. Continue with remaining commands? (y/n): ").strip().lower()
                if cont != 'y':
                    print("Aborting remaining commands.")
                    break
            continue

        # 2. VERY IMPORTANT: Human Confirmation
        try:
            confirm = input(f"Do you want to execute this command? (y/n/skip_all): ").strip().lower()
        except EOFError:  # Handle non-interactive environments or Ctrl+D
            print("No user input received (EOF). Assuming 'n' for safety.")
            confirm = 'n'

        if confirm == 'y':
            try:
                print(f"Executing: `{command_string}`")
                # Using shell=True allows for shell features like pipes, wildcards, etc.,
                # directly in the command_string. This is powerful but carries security risks
                # if the command_string is not trustworthy. Our blocklist and Zuck's prompt
                # try to mitigate this, but caution is always advised.
                # For commands not needing shell features, shell=False with shlex.split(command_string)
                # is a safer alternative.
                result = subprocess.run(command_string, shell=True, capture_output=True, text=True, check=False)

                if result.stdout:
                    print("--- Output ---")
                    print(result.stdout.strip())
                    all_stdout_results.append(result.stdout)
                    print("--------------")
                if result.stderr:
                    print("--- Error Output ---")
                    print(result.stderr.strip())
                    all_stderr_results.append(result.stderr)
                    print("------------------")

                if result.returncode != 0:
                    print(f"Command failed with return code {result.returncode}.")
                    overall_success = False
                else:
                    print("Command executed successfully.")

            except FileNotFoundError:
                error_msg = f"Error: Command not found. Make sure '{command_string.split()[0]}' is installed and in your PATH."
                print(error_msg)
                all_stderr_results.append(error_msg)
                overall_success = False
            except Exception as e:
                error_msg = f"An error occurred while trying to execute the command: {e}"
                print(error_msg)
                all_stderr_results.append(error_msg)
                overall_success = False

        elif confirm == 'skip_all':
            print("Execution skipped for this and all subsequent commands by user.")
            all_stderr_results.append(f"Execution skipped by user for: {command_string} (and subsequent)")
            overall_success = False  # Mark as not fully successful if any command is skipped
            break  # Exit the loop for commands
        else:  # 'n' or any other input
            print("Execution skipped by user for this command.")
            all_stderr_results.append(f"Execution skipped by user for command: {command_string}")
            overall_success = False  # Mark as not fully successful if any command is skipped

    return "\n".join(all_stdout_results).strip(), "\n".join(all_stderr_results).strip(), overall_success


# --- Main Interaction Loop ---
def main():
    print("Initializing Zuck, your Cybersecurity Agent...")
    try:
        model = genai.GenerativeModel(
            model_name=ZUCK_MODEL_NAME,
            system_instruction=ENHANCED_SYSTEM_INSTRUCTION,
            generation_config=genai.types.GenerationConfig(
                temperature=0.3  # Lower temperature for more deterministic/less creative commands
            )
        )
        chat_session = model.start_chat(history=[])  # Start a chat session for context if needed
        print("Zuck is ready. Type 'exit' or 'quit' to end.")
    except Exception as e:
        print(f"Error initializing the model or chat session: {e}")
        return

    while True:
        try:
            user_prompt = input("\nAsk Zuck: ")
        except EOFError:
            print("\nExiting due to EOF.")
            break
        except KeyboardInterrupt:
            print("\nExiting due to user interrupt.")
            break

        if user_prompt.lower() in ['exit', 'quit']:
            print("Zuck signing off. Stay safe!")
            break

        if not user_prompt.strip():
            continue

        print("Zuck is thinking...")
        try:
            # Send message to the chat session
            response = chat_session.send_message(user_prompt)
            proposed_text = response.text.strip()
        except Exception as e:
            print(f"Error getting response from GenAI: {e}")
            continue

        # For debugging Zuck's raw output:
        # print(f"\n--- Zuck's Raw Proposal ---\n{proposed_text}\n--------------------------")

        if proposed_text.startswith("#ASK_USER:"):
            question = proposed_text[len("#ASK_USER:"):].strip()
            print(f"\nZuck asks for clarification: {question}")
        else:
            commands_to_process = []
            info_messages = []

            for line in proposed_text.split('\n'):
                stripped_line = line.strip()
                if not stripped_line:  # Skip empty lines
                    continue
                if stripped_line.startswith("#INFO:"):
                    info_messages.append(stripped_line[len("#INFO:"):].strip())
                else:
                    commands_to_process.append(stripped_line)

            if info_messages:
                print("\nZuck provides the following information:")
                for info in info_messages:
                    print(f"- {info}")

            final_commands_str = "\n".join(commands_to_process)

            if final_commands_str:
                # The execute_proposed_commands function handles safety and individual confirmation
                stdout_res, stderr_res, success = execute_proposed_commands(final_commands_str)

                # Optional: Prepare context for next turn based on execution results
                # This part is simple; a more advanced version would summarize or select key info.
                # if not success and stderr_res:
                #     print("\nZuck: There were issues with the last command(s).")
                #     # The errors are already in chat_session.history via user/model turns
                # elif success and stdout_res:
                #     print("\nZuck: Commands executed.")
                # elif success:
                #     print("\nZuck: Commands executed (no output).")

            elif not proposed_text.startswith("#ASK_USER:"):  # Only print if not an ask_user and no commands
                print("\nZuck did not propose a command or ask a question this time.")
                # Check if the response might be conversational due to a misunderstanding of the prompt
                if proposed_text and not any(
                        proposed_text.startswith(p) for p in ["#ASK_USER:", "#INFO:"]) and not commands_to_process:
                    print(f"Zuck said: {proposed_text}")


if __name__ == "__main__":
    main()