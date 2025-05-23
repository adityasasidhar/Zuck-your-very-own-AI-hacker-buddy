from google import genai

client = genai.Client(api_key='AIzaSyCbKnqJV9LNu8XxxSoYkAlFYyLLvy1NnMo')
chat = client.chats.create(model="gemini-2.0-flash")

response = chat.send_message("I have 2 dogs in my house.")
print(response.text)

response = chat.send_message("How many paws are in my house?")
print(response.text)

for message in chat.get_history():
    print(f'role - {message.role}',end=": ")
    print(message.parts[0].text)