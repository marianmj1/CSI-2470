import socket
import threading
import bcrypt
import pickle

clients = []  # List of usernames (first name) and default password is 123 to make it easy
users = {
    "Marian": bcrypt.hashpw("123".encode(), bcrypt.gensalt()),
    "Spencer": bcrypt.hashpw("123".encode(), bcrypt.gensalt()),
    "Mason": bcrypt.hashpw("123".encode(), bcrypt.gensalt())
}


# Security username/password
def authenticate(username, password):
    if username in users and bcrypt.checkpw(password.encode(), users[username]):
        return True
    return False


# Handle client communication
def handle_client(conn, addr):
    print(f"New connection from {addr}")

    clients.append(conn)

    # Authenticate user
    try:
        credentials = pickle.loads(conn.recv(1024))
        username, password = credentials['username'], credentials['password']

        if not authenticate(username, password):
            conn.sendall(pickle.dumps({"status": "failed", "message": "Authentication failed"}))
            conn.close()
            return

        conn.sendall(pickle.dumps({"status": "success", "message": "Welcome!"}))
    except Exception as e:
        print(f"Error during authentication: {e}")
        conn.close()
        return


    while True:
        try:
            message = conn.recv(1024).decode('utf-8')
            if message:
                print(f"Message from {addr}: {message}")
                broadcast_message(message, conn)
            else:
                break
        except:
            break


    clients.remove(conn)
    conn.close()


# Function to broadcast messages to all clients except the sender
def broadcast_message(message, sender_conn):
    for client in clients:
        if client != sender_conn:
            try:
                client.send(message.encode('utf-8'))
            except:
                continue


# Start the server
def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 5555))
    server_socket.listen(5)
    print("Server started, waiting for clients...")

    while True:
        conn, addr = server_socket.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


start_server()





