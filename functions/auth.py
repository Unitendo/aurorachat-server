# Authentication related functions
import bcrypt
import os

USERNAME_MAX_CHARS = int(os.getenv("AUC_USERNAME_MAX_CHARS", 25))
PASSWORD_MAX_CHARS = int(os.getenv("AUC_PASSWORD_MAX_CHARS", 40))
DISALLOWED_USERNAMES = [
    u.strip()
    for u in (os.getenv("AUC_DISALLOWED_USERNAMES") or "").split("|")
    if u.strip()
]

def checkAdmin(user, dbcursor):
    dbcursor.execute("SELECT type FROM admins WHERE uname = ?", (user,))
    if dbcursor.fetchone():
        return True
    return False

def checkStaff(user, dbcursor):
    dbcursor.execute("SELECT type FROM admins WHERE uname = ?", (user,))
    row = dbcursor.fetchone()
    if row and row[0] == "staff":
        return True
    return False

def checkBan(type, val, dbcursor):
    if type == "user":
        dbcursor.execute("SELECT 1 FROM bannedusers WHERE uname = ?", (val,))
    elif type == "ip":
        dbcursor.execute("SELECT 1 FROM bannedips WHERE ip = ?", (val,))
    if dbcursor.fetchone():
        return True
    return False

def makeAccount(client, data, ip, dbcursor, userdb):
    if all(
        key in data for key in ["username", "password"]
    ):  # Make sure username and password exist
        username = data["username"]
        password = data["password"]
        if (
            "\\" in username
            or "/" in username
            or " " in username
            or len(username) > USERNAME_MAX_CHARS
        ):
            print(f"Illegal username: '{username}'")
            return {"data": "ILLEGAL"}
        if any(item in username for item in DISALLOWED_USERNAMES):
            print(f"Disallowed username: '{username}'")
            return {"data": "ILLEGAL"}
        if len(password) > PASSWORD_MAX_CHARS:
            print("Illegal password, exceeded char limit.")
            return {"data": "ILLEGAL"}
        exists = dbcursor.execute(
            "SELECT uname FROM users WHERE uname = ?", (username,)
        )
        if not dbcursor.fetchone():
            hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
            dbcursor.execute(
                "INSERT INTO users (uname, hashedpw, ip, known) VALUES (?, ?, ?, ?)",
                (username, hashed, ip, False),
            )
            userdb.commit()
            print(f"Account '{username}' created")
            return {"data": "USR_CREATED"}
        else:
            print(f"Account creation attempt when it already existed: '{username}'")
            return {"data": "USR_IN_USE"}, 409

def loginAccount(client, data, ip, dbcursor, userdb, broadcast):
    if all(
        key in data for key in ["username", "password"]
    ):  # Make sure username and password exist
        username = data["username"]
        password = data["password"]
        if not checkBan("user", username, dbcursor):
            dbcursor.execute("SELECT hashedpw FROM users WHERE uname = ?", (username,))
            row = dbcursor.fetchone()
            hashedpw = row[0] if row else None
            if hashedpw:
                if bcrypt.checkpw(password.encode("utf-8"), hashedpw):
                    print(f"User '{username}' logged in with IP '{ip}'")
                    client.username = username
                    client.loggedin = True
                    dbcursor.execute(
                        "UPDATE users SET ip = ? WHERE uname = ?", (ip, username)
                    )
                    userdb.commit()
                    broadcast(f"*[SYSTEM]*: {username} has joined the chat.\n")
                    return {"data": "LOGIN_OK"}
                else:
                    return {"data": "LOGIN_WRONG_PASS"}, 401
            else:
                return {"data": "LOGIN_FAKE_ACC"}, 401
        else:
            return {"data": "BANNED"}, 403