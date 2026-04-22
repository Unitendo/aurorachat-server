# Messaging related functions
import time
import os
from better_profanity import profanity

RATE_LIMIT_MS = int(os.getenv("AUC_RATE_LIMIT_MS", 1998))
MAX_MESSAGE_LENGTH = int(os.getenv("AUC_MAX_MESSAGE_LENGTH", 457))
RAWCHAT_KEY = os.getenv("AUC_RAWCHAT_KEY", "")

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

def processMessage(client, data, ip, dbcursor, userdb, broadcast_func, checkAdmin_func, checkBan_func, maintenance, rate_limit, syscmd, tcp_clients, socketio, userCount):
    if data["cmd"] == "RAWCHAT":
        if data["rawkey"] == RAWCHAT_KEY:
            broadcast_func(f"{data['content']}\n")
            print(f"Message sent with RAWCHAT by IP '{ip}': '{data['content']}'")
            return {"data": "MSG_SENT"}
        else:
            print(f"IP '{ip}' tried to utilize RAWCHAT without the key.")
            return {"data": "INVALID_KEY"}, 403
    else:
        if client.loggedin:
            if len(data["platform"]) > 30:
                return {"data": "ILLEGAL; PLATFORM TOO LONG"}, 400

            if checkBan_func("user", client.username, dbcursor):
                print(f"A banned user '{client.username}' tried to send a message.")
                return {"data": "BANNED"}, 403
            if checkBan_func("ip", ip, dbcursor):
                print(f"A banned IP '{ip}' tried to send a message.")
                return {"data": "BANNED"}, 403

            if data["cmd"] == "CHAT":
                typeIdentifier = "<>"
            elif data["cmd"] == "BOTCHAT":
                typeIdentifier = "[]"
            elif data["cmd"] == "INTCHAT":
                typeIdentifier = "{}"
            tag = " "
            dbcursor.execute(
                "SELECT tag FROM usertags WHERE uname = ?", (client.username,)
            )
            row = dbcursor.fetchone()
            if row:
                tag = row[0]
            if tag != " ":
                tag = f" ~{tag.strip()}~ "
            elif checkAdmin_func(client.username, dbcursor):
                tag = " ~Moderator~ "
            usernameWithIdentifier = f"({data['platform']}){tag}{typeIdentifier[0]}{client.username}{typeIdentifier[1]}"

            censored_msg = profanity.censor(data["content"].strip(), "*")
            censored_msg = repr(censored_msg).strip("'")
            if not checkAdmin_func(client.username, dbcursor):
                now = int(time.time() * 1000)
                last_msg = rate_limit.get(client, 0)
                if now - last_msg < RATE_LIMIT_MS:
                    return {"data": "SPAM", "limit": str(RATE_LIMIT_MS)}
                rate_limit[client] = now

            if len(censored_msg) > MAX_MESSAGE_LENGTH:
                return {"data": "TOOLONG", "limit": str(MAX_MESSAGE_LENGTH)}
            if censored_msg.startswith("/ban ip "):  # redact ips
                censored_msg = "/ban ip [redacted]"
            if censored_msg.startswith("/unban ip "):
                censored_msg = "/unban ip [redacted]"
            if maintenance:
                if checkAdmin_func(client.username, dbcursor):
                    broadcast_func(f"{usernameWithIdentifier}: {censored_msg}\n")
                    cmdResult = syscmd.checkCmd(
                        client.username, data["content"], broadcast_func, userdb, dbcursor
                    )
                    print(
                        f"Message sent from IP '{ip}' during maintenance mode: '{usernameWithIdentifier}: {censored_msg}'"
                    )
                else:
                    print(
                        f"Message from IP '{ip}' could not send due to server being in maintenance mode: '{usernameWithIdentifier}: {censored_msg}'"
                    )
                    return {"data": "MAINTENANCE_MODE"}
            else:
                broadcast_func(f"{usernameWithIdentifier}: {censored_msg}\n")
                cmdResult = syscmd.checkCmd(
                    client.username, data["content"], broadcast_func, userdb, dbcursor
                )
                print(
                    f"Message sent from IP '{ip}': '{usernameWithIdentifier}: {censored_msg}'"
                )
            return {"data": "MSG_SENT"}
        else:
            return {"data": "NO_LOGIN"}, 401