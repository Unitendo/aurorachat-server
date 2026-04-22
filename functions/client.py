# Client handling functions
import time
import os

LATEST_VERSION = float(os.getenv("AUC_LATEST_VERSION", 4.5))
RATE_LIMIT_MS = int(os.getenv("AUC_RATE_LIMIT_MS", 1998))

class Client:
    def __init__(self):
        self.username = None
        self.loggedin = False

def handleClient(ip, data, checkBan_func, dbcursor, clients, connection_times):
    if checkBan_func("ip", ip):
        print(f"A banned IP tried to connect: '{ip}'")
        return {"data": "BANNED"}, 403

    now_ms = int(time.time() * 1000)
    last_connection = connection_times.get(ip, 0)

    if now_ms - last_connection < RATE_LIMIT_MS:
        print(f"Too many connections from IP '{ip}'")
        return {"data": "RATE_LIMIT"}

    connection_times[ip] = now_ms

    client = Client()
    clients[ip] = client

    version = data.get("version")

    if version is None:
        return {"data": "NO_VERSION"}, 400

    try:
        version = float(version)
    except:
        return {"data": "BAD_VERSION"}, 400

    if version != LATEST_VERSION:
        print(f"Outdated client from IP '{ip}'.")
        return {"data": "CONNECT_OK", "info": "OUTDATED"}

    print(f"Client connection established from IP '{ip}'.")
    return {"data": "CONNECT_OK"}