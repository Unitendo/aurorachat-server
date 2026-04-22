# TCP server functions
import socket
import threading

def broadcast(message, tcp_clients, socketio, userCount):
    for client in tcp_clients[:]:
        try:
            client.sendall(message.encode("utf-8"))
        except:
            userCount -= 1
            tcp_clients.remove(client)

    socketio.emit("message", message)

def systembroadcast(message, tcp_clients, socketio):
    for client in tcp_clients[:]:
        try:
            client.sendall(
                "(Server) *[SYSTEM]*: ".encode("utf-8") + message.encode("utf-8")
            )
        except:
            tcp_clients.remove(client)

    socketio.emit("message", message)

def handle_tcp_client(client_socket, tcp_clients, userCount):
    try:
        while True:
            data = client_socket.recv(1024)
            if not data:
                break
    except:
        pass
    finally:
        if client_socket in tcp_clients:
            tcp_clients.remove(client_socket)
        client_socket.close()

def start_tcp_server(TCP_PORT, tcp_clients, userCount):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", TCP_PORT))
    server.listen(5)
    print(f"AuroraTCP running on port {TCP_PORT}")

    while True:
        client_sock, addr = server.accept()
        print("Client connected through TCP")
        tcp_clients.append(client_sock)
        userCount += 1
        t = threading.Thread(target=handle_tcp_client, args=(client_sock, tcp_clients, userCount), daemon=True)
        t.start()