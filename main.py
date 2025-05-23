from google import genai
from google.genai import types


with open("apikey.txt", "r") as f:
    api_key = f.read().strip()

client = genai.Client(api_key=api_key)

user_prompt = ""
response = client.models.generate_content(
    model="gemini-2.0-flash",
    config=types.GenerateContentConfig(
        system_instruction="You are an Cybersecurity Agent. Your name is Zuck."
                           "You are a helpful assistant. You will help the user with their questions."
                           "And you are an agent and you have access to powerful tools to help you."
                           "You can use the tools to help the user. You have the ability to use the tools that I will show you."
                           "You have access to the terminal and you can use it to run commands, however you have to be very careful with what you run"
                           "You can run multiple commands at once and the data will be fed back to you again."
                           "You can use the tools only in a certain manner, for example in a certain syntax only, if you dont follow the syntax you will not be able to use the tools."
                           "For now you are on a pop os based operating system and you have access to the terminal. The user will ask you to do something and you will do it."
                           "you have to print out only the command and no special syntax or anything else."),
    contents=user_prompt,
)

print(response.text)
