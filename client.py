import socket
import pickle
import tkinter as tk
from tkinter import scrolledtext
from tkinter import messagebox
import threading

# Connect to the server
server_address = ('localhost', 5555)
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(server_address)


def connect_to_server():

    new_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    new_socket.connect(server_address)
    return new_socket


def send_credentials(username, password):

    global client_socket
    while True:  # Retry loop for incorrect passwords
        try:
            credentials = {"username": username, "password": password}
            client_socket.sendall(pickle.dumps(credentials))
            response = pickle.loads(client_socket.recv(1024))

            if response["status"] == "failed":
                messagebox.showerror("Login Failed", "Incorrect username or password. Please try again.")
                # Retry credentials
                username = input("Enter username: ")
                password = input("Enter password: ")
                # Reconnect to the server
                client_socket.close()
                client_socket = connect_to_server()
            else:
                messagebox.showinfo("Login Success", response["message"])
                return True
        except Exception as e:
            messagebox.showerror("Connection Error", f"Error: {e}")
            exit()


# Initial connection
client_socket = connect_to_server()

# Prompt the player for username and password
username = input("Enter username: ")
password = input("Enter password: ")

# Authenticate before starting the chat
if not send_credentials(username, password):
    exit()

# send messages
def send_message():
    message = message_entry.get()
    if message:
        client_socket.send(message.encode('utf-8'))
        message_entry.delete(0, tk.END)  # Clear the input field

# Receive messages
def receive_messages():
    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8')
            chat_box.config(state='normal')  # Enable chat box
            chat_box.insert(tk.END, message + '\n')  # Display received message in chat box
            chat_box.config(state='disabled')  # Disable chat box again
            chat_box.yview(tk.END)  # Scroll to the bottom
        except:
            break

# GUI
window = tk.Tk()
window.title("Chat Application CSI 2470 Project")

chat_box = scrolledtext.ScrolledText(window, width=50, height=20, wrap=tk.WORD, state='disabled')
chat_box.pack(padx=10, pady=10)

message_entry = tk.Entry(window, width=40)
message_entry.pack(padx=10, pady=5)

send_button = tk.Button(window, text="Send", width=10, command=send_message)
send_button.pack(pady=5)

threading.Thread(target=receive_messages, daemon=True).start()

# Start the GUI
window.mainloop()


