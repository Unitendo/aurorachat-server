from flask import (
    Flask,
    jsonify,
    request,
    send_from_directory,
    render_template,
    session,
    redirect,
    url_for,
)
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import threading
import time
import sys
from better_profanity import profanity
import os.path
import os
import bcrypt
import hashlib
import socket
from dotenv import load_dotenv
import sqlite3
import json

import syscmd

from functions import auth, messaging, tcp, client, utils
load_dotenv()
LATEST_VERSION = float(os.getenv("AUC_LATEST_VERSION", 4.5))
HOST = os.getenv("AUC_HOST", "0.0.0.0")
HTTP_PORT = int(os.getenv("AUC_HTTP_PORT", 8080)) # Changed to 8080 for cloudflare, not 80 because Main unitendo site uses it
TCP_PORT = int(os.getenv("AUC_TCP_PORT", 8880)) # Changed to 8880 also for cloudflare
RATE_LIMIT_MS = int(os.getenv("AUC_RATE_LIMIT_MS", 1998))
MAX_MESSAGE_LENGTH = int(os.getenv("AUC_MAX_MESSAGE_LENGTH", 457))
USERNAME_MAX_CHARS = int(os.getenv("AUC_USERNAME_MAX_CHARS", 25))
PASSWORD_MAX_CHARS = int(os.getenv("AUC_PASSWORD_MAX_CHARS", 40))
FLASK_SECRET_KEY = os.getenv("AUC_FLASK_SECRET_KEY", "")
RAWCHAT_KEY = os.getenv("AUC_RAWCHAT_KEY", "")
DISALLOWED_USERNAMES = [
    u.strip()
    for u in (os.getenv("AUC_DISALLOWED_USERNAMES") or "").split("|")
    if u.strip()
]
DISALLOWED_WORDS = [
    w.strip() for w in (os.getenv("AUC_DISALLOWED_WORDS") or "").split("|") if w.strip()
]


userdb = sqlite3.connect("users.db", check_same_thread=False)
dbcursor = userdb.cursor()

dbcursor.execute(
    "CREATE TABLE IF NOT EXISTS users (uname TEXT, hashedpw BLOB, ip TEXT, known BOOL)"
)
dbcursor.execute("CREATE TABLE IF NOT EXISTS bannedusers (uname TEXT, reason TEXT)")
dbcursor.execute("CREATE TABLE IF NOT EXISTS bannedips (ip TEXT, reason TEXT)")
dbcursor.execute("CREATE TABLE IF NOT EXISTS usertags (uname TEXT, tag TEXT)")
dbcursor.execute("CREATE TABLE IF NOT EXISTS admins (uname TEXT, type TEXT)")
userdb.commit()

if not os.path.exists("maintenanceMode_Active.conf"):
    with open("maintenanceMode_Active.conf", "w") as f:
        f.write("False")
with open("maintenanceMode_Active.conf") as f:
    if f.read().strip() == "False":
        maintenance = False
    else:
        maintenance = True
# virt u put this globalization here and its horrifying (-orstando)
# global userCount
userCount = 0

# -- TCP Sockets --
tcp_clients = []



# --- Global State ---
clients = {}
rate_limit = {}
connection_times = {}
msg_lock = threading.Lock()

profanity.load_censor_words()
profanity.add_censor_words(DISALLOWED_WORDS)

app = Flask(__name__)

app.secret_key = FLASK_SECRET_KEY

CORS(app)

socketio = SocketIO(app, cors_allowed_origins="*")

socketio.start_background_task(tcp.start_tcp_server, TCP_PORT, tcp_clients, userCount)

def broadcast(message):
    tcp.broadcast(message, tcp_clients, socketio, userCount)


# --- Client Handling ---
# remove trailing slash (https://stackoverflow.com/a/40365514)
app.url_map.strict_slashes = False


@app.before_request
def clear_trailing():
    rp = request.path
    if rp != "/" and rp.endswith("/"):
        return redirect(rp[:-1])


@app.route("/rules")
def getRules():
    return "rules"


@app.route("/rules/silly")
def sillyRules():
    return "silly rules"


@app.route("/faq")
def getFaq():
    return "faq"


@app.route("/changelog")
def getChangelog():
    return "changelog"


@app.route("/api")
def error405():
    print(f"IP '{request.remote_addr}' accessed the API without using POST.")
    return "Please use POST instead.", 405


@app.route("/")
def rootRedirect():
    return redirect("/api")


# --- Main Server Logic ---
@app.route("/api", methods=["POST"])
def process_request():
    request_json = request.get_json(silent=True)
    if not request_json:
        return {"data": "NO_JSON"}, 400

    ip = request.remote_addr
    cmd = request_json.get("cmd")
    if cmd == "CONNECT":
        return client.handleClient(ip, request_json, auth.checkBan, dbcursor, clients, connection_times)

    # Make sure client exists for any command other than CONNECT
    client_obj = clients.get(ip)
    if not client_obj:
        return {"data": "NOT_CONNECTED"}, 400

    if cmd == "MAKEACC":
        return auth.makeAccount(client_obj, request_json, ip, dbcursor, userdb)

    elif cmd == "LOGINACC":
        return auth.loginAccount(client_obj, request_json, ip, dbcursor, userdb, broadcast)

    elif cmd in ["CHAT", "BOTCHAT", "INTCHAT", "RAWCHAT"]:
        return messaging.processMessage(client_obj, request_json, ip, dbcursor, userdb, broadcast, auth.checkAdmin, auth.checkBan, maintenance, rate_limit, syscmd, tcp_clients, socketio, userCount)

    else:
        return {"data": "BADCMD"}, 400


# Grab auroraweb
@app.route("/web")
def auoraweb():
    return render_template("auroraweb.html", version=LATEST_VERSION)


@app.route("/stats")
def getStats():
    dbcursor.execute("SELECT COUNT(*) FROM users")
    row = dbcursor.fetchone()
    userCount = row[0] if row else 0

    dbcursor.execute("SELECT COUNT(*) FROM bannedusers")
    row = dbcursor.fetchone()
    bannedUserCount = row[0] if row else 0

    dbcursor.execute("SELECT COUNT(*) FROM bannedips")
    row = dbcursor.fetchone()
    bannedIpCount = row[0] if row else 0

    dbcursor.execute("SELECT COUNT(*) FROM admins")
    row = dbcursor.fetchone()
    adminCount = row[0] if row else 0
    return f"""
        <p>Stats</p><br>
        <p>Users: {str(userCount)}</p>
        <p>Banned users: {str(bannedUserCount)}</p>
        <p>Banned IPs: {str(bannedIpCount)}</p>
        <p>Admins: {str(adminCount)}</p>
    """


# --- Admin Panel ---
@app.route("/style.css", methods=["GET"])
def getCss():
    return """
    <style>
        a {color:blue;}
        a:visited{color:blue;}
    </style>
    """


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        dbcursor.execute("SELECT type FROM admins WHERE uname = ?", (username,))
        row = dbcursor.fetchone()
        if not row:
            return "Invalid username or password", 401
        admintype = row[0]

        dbcursor.execute("SELECT hashedpw FROM users WHERE uname = ?", (username,))
        row = dbcursor.fetchone()
        if not row:
            return "Invalid username or password", 401
        stored_hash = row[0]

        if bcrypt.checkpw(password.encode("utf-8"), stored_hash):
            if admintype == "staff":
                session["staff"] = True
            session["admin"] = True
            return redirect("/admin")

        return "Invalid username or password", 401

    return """
    <form method="POST">
        <input type="text" name="username" placeholder="Username" required>
        <input type="password" name="password" placeholder="Password" required>
        <button type="submit">Login</button>
    </form>
    """


@app.route("/admin")
def admin():
    if not session.get("admin"):
        return redirect("/admin/login")
    result = """
        <link rel='stylesheet' href='/style.css'>
        <p>Admin Panel</p>
        <a href="/admin/ban">Ban/unban user or ip</a><br>
        <a href="/admin/banipfromuname">Ban ip based on username</a><br>
        <a href="/admin/managetags">Tag management</a><br>
        <a href="/admin/stats">Statistics</a><br>
    """
    if session.get("staff"):
        result = result + "<a href='/staff'>Staff Panel</a>"
    return result


@app.route("/admin/ban", methods=["GET", "POST"])
def ban_user():
    if not session.get("admin"):
        return "Unauthorized", 403
    if request.method == "POST":
        value = request.form["value"]
        reason = request.form["reason"]
        bantype = request.form["type"]  # user / ip
        mode = request.form["mode"]  # ban / unban
        if bantype == "user":
            tableName = "bannedusers"
            bantype = "uname"
        elif bantype == "ip":
            tableName = "bannedips"
        if mode == "ban":
            dbcursor.execute(
                f"INSERT INTO {tableName} ({bantype},reason) VALUES (?,?)",
                (value, reason),
            )
        elif mode == "unban":
            dbcursor.execute(f"DELETE FROM {tableName} WHERE {bantype} = ?", (value,))
        userdb.commit()
        return f"<link rel='stylesheet' href='/style.css'><p>{request.form['mode'].title()} successful.</p><a href='/admin'>Back to admin panel</a>"
    return """
    <link rel='stylesheet' href='/style.css'>
    <form method="POST">
        <input name="value" id="value" placeholder="Username to ban" required><br>
        <input name="reason" id="reason" placeholder="Ban reason"><br id="reasonbr">
        <select name="type" id="type" onchange="change()">
            <option value="user">User</option>
            <option value="ip">IP</option>
        </select>
        <select name="mode" id="mode" onchange="change()">
            <option value="ban">Ban</option>
            <option value="unban">Unban</option>
        </select><br>
        <button id="submit">Ban User</button><br>
    </form>
    <a href='/admin'>Back to admin panel</a>
    <script>
    function change() {
        if (document.getElementById("type").value == "user") {
            if (document.getElementById("mode").value == "ban") {
                document.getElementById("submit").innerHTML = "Ban User";
                document.getElementById("value").setAttribute('placeholder','Username to ban');
                document.getElementById("reason").style.display="inline";
                document.getElementById("reasonbr").style.display="inline"
            } else if (document.getElementById("mode").value == "unban") {
                document.getElementById("submit").innerHTML = "Unban User";
                document.getElementById("value").setAttribute('placeholder','Username to unban');
                document.getElementById("reason").style.display="none";
                document.getElementById("reasonbr").style.display="none"
            }
        } else if (document.getElementById("type").value == "ip") {
            if (document.getElementById("mode").value == "ban") {
                document.getElementById("submit").innerHTML = "Ban IP";
                document.getElementById("value").setAttribute('placeholder','IP to ban');
                document.getElementById("reason").style.display="inline";
                document.getElementById("reasonbr").style.display="inline"
            } else if (document.getElementById("mode").value == "unban") {
                document.getElementById("submit").innerHTML = "Unban IP";
                document.getElementById("value").setAttribute('placeholder','IP to unban');
                document.getElementById("reason").style.display="none";
                document.getElementById("reasonbr").style.display="inline"
            }
        }
    }
    </script>
    """


@app.route("/admin/banipfromuname", methods=["GET", "POST"])
def banIpFromUsername():
    if not session.get("admin"):
        return "Unauthorized", 403
    if request.method == "POST":
        dbcursor.execute(
            "SELECT ip FROM users WHERE uname = ?", (request.form["username"],)
        )
        row = dbcursor.fetchone()
        if not row:
            return "User not found", 404
        ip = row[0]
        if request.form["mode"] == "ban":
            dbcursor.execute(
                f"INSERT INTO bannedips (ip,reason) VALUES (?,?)",
                (ip, request.form["reason"]),
            )
        elif request.form["mode"] == "unban":
            dbcursor.execute(f"DELETE FROM bannedips WHERE ip = ?", (ip,))
        userdb.commit()
        return f"<link rel='stylesheet' href='/style.css'><p>IP successfully {request.form['mode']}ned.</p><a href='/admin'>Back to admin panel</a>"
    else:
        return """
            <link rel='stylesheet' href='/style.css'>
            <form method="POST">
                <input name="username" placeholder="Username"><br>
                <input name="reason" placeholder="Reason"><br>
                <select name="mode" id="mode">
                    <option value="ban">Ban</option>
                    <option value="unban">Unban</option>
                </select>
                <input type="submit" value="Submit">
            </form>
            <a href='/admin'>Back to admin panel</a>
        """


@app.route("/admin/managetags", methods=["GET", "POST"])
def manageTags():
    if not session.get("admin"):
        return "Unauthorized", 403
    if request.method == "POST":
        if request.form["mode"] == "add":
            dbcursor.execute(
                "INSERT INTO usertags (uname,tag) VALUES (?,?)",
                (request.form["username"], request.form["tag"]),
            )
        elif request.form["mode"] == "remove":
            dbcursor.execute(
                "DELETE FROM usertags WHERE uname = ?", (request.form["username"],)
            )
        userdb.commit()
        return f"<link rel='stylesheet' href='/style.css'><p>Tag {request.form['mode']}ed.<p><a href='/admin'>Back to admin panel</a>"
    return """
        <link rel='stylesheet' href='/style.css'>
        <form method="POST">
            <input name="username" placeholder="Username"><br>
            <input name="tag" placeholder="Tag"><br>
            <select name="mode">
                <option value="add">Add</option>
                <option value="remove">Remove</option>
            </select>
            <input type="submit" value="Submit">
        </form>
        <a href='/admin'>Back to admin panel</a>
    """


# --- Staff Panel ---
@app.route("/staff")
def staff():
    if not session.get("staff"):
        return "Unauthorized", 403
    return """
        <link rel='stylesheet' href='/style.css'>
        <p>Staff Panel</p>
        <a href="/staff/manageadmins">Admin/staff management</a><br>
        <a href="/staff/getip">Get an IP based on username</a><br>
        <a href="/staff/managedb">Database management</a><br>
        <a href="/staff/maintenance">Toggle maintenance mode</a><br>
        <a href="/admin">Return to admin panel</a>
    """


@app.route("/staff/manageadmins", methods=["GET", "POST"])
def manageAdmins():
    if request.method == "POST":
        if request.form["mode"] == "add":
            dbcursor.execute(
                "INSERT INTO admins (uname,type) VALUES (?,?)",
                (request.form["username"], request.form["type"]),
            )
        elif request.form["mode"] == "remove":
            if request.form["type"] == "admin":
                dbcursor.execute(
                    "DELETE FROM admins WHERE uname = ?", (request.form["username"],)
                )
            elif request.form["type"] == "staff":
                dbcursor.execute(
                    "UPDATE admins SET type = 'admin' WHERE uname = ?",
                    (request.form["username"],),
                )
        userdb.commit()
        return f"<link rel='stylesheet' href='/style.css'><p>{request.form['type'].title()} successfully {request.form['mode']}ed.</p><a href='/staff'>Back to staff panel</a>"
    return """
        <link rel='stylesheet' href='/style.css'>
        <form method="POST">
            <input name="username" placeholder="username">
            <select name="type">
                <option value="admin">Admin</option>
                <option value="staff">Staff</option>
            </select>
            <select name="mode">
                <option value="add">Add</option>
                <option value="remove">Remove</option>
            </select>
            <input type="submit" value="Submit">
        </form>
        <a href='/staff'>Back to staff panel</a>
    """


@app.route("/staff/getip", methods=["GET", "POST"])
def getIp():
    if request.method == "POST":
        dbcursor.execute(
            "SELECT ip FROM users WHERE uname = ?", (request.form["username"],)
        )
        row = dbcursor.fetchone()
        if not row:
            return "User not found", 404
        result = row[0]
        return f"<link rel='stylesheet' href='/style.css'><p>IP of {request.form['username']}: {result}</p><a href='/staff'>Back to staff panel</a>"
    return """
        <link rel='stylesheet' href='/style.css'>
        <form method="POST">
            <input name="username" placeholder="Username">
            <input type="submit" value="Submit">
        </form>
        <a href='/staff'>Back to staff panel</a>
    """


@app.route("/staff/managedb", methods=["GET", "POST"])
def manageDb():
    if request.method == "POST":
        dbcursor.execute(request.form["query"], ())
        result = str(dbcursor.fetchall())
        userdb.commit()
        return f"<link rel='stylesheet' href='/style.css'><p>Result: {result}</p><a href='/staff'>Back to staff panel</a>"
    return """
        <link rel='stylesheet' href='/style.css'>
        <form method="POST">
            <input name="query" placeholder="Query">
            <input type="submit" value="Submit">
        </form>
        <a href='/staff'>Back to staff panel</a>
    """


@app.route("/staff/maintenance", methods=["GET", "POST"])
def maintenanceMode():
    global maintenance
    if request.method == "POST":
        with open("maintenanceMode_Active.conf", "r+") as f:
            if f.read().strip() == "True":
                f.seek(0)
                f.truncate()
                f.write("False")
                maintenance = False
                result = "de"
            else:
                f.seek(0)
                f.truncate()
                f.write("True")
                maintenance = True
                result = ""
            return f"<link rel='stylesheet' href='/style.css'><p>Maintenance mode {result}activated.</p><a href='/staff'>Back to staff panel</a>"
    else:
        if maintenance:
            status = "on"
        else:
            status = "off"
        return f"<link rel='stylesheet' href='/style.css'><p>Maintenance mode is currently {status}.</p><form method='POST'><input type='submit' value='Toggle'></form><a href='/staff'>Back to staff panel</a>"


@socketio.on("connect")
def handle_connect():
    print("WS Connection Established.")
    socketio.emit("message", "Connected!")


if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=HTTP_PORT, use_reloader=False)
