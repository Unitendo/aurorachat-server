from flask import Flask, jsonify, request, send_from_directory, render_template, session, redirect, url_for
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
import threading
import socket
from dotenv import load_dotenv
import sqlite3
import json

import syscmd

# --- Configuration ---
load_dotenv()
LATEST_VERSION = float(os.getenv('AUC_LATEST_VERSION', 4.5))
HOST = os.getenv('AUC_HOST', "0.0.0.0")
HTTP_PORT = int(os.getenv('AUC_HTTP_PORT', 3072))
TCP_PORT = int(os.getenv('AUC_TCP_PORT', 4040))
RATE_LIMIT_MS = int(os.getenv('AUC_RATE_LIMIT_MS', 1998))
MAX_MESSAGE_LENGTH = int(os.getenv('AUC_MAX_MESSAGE_LENGTH', 457))
USERNAME_MAX_CHARS = int(os.getenv('AUC_USERNAME_MAX_CHARS', 25))
PASSWORD_MAX_CHARS = int(os.getenv('AUC_PASSWORD_MAX_CHARS', 40))
FLASK_SECRET_KEY = os.getenv('AUC_FLASK_SECRET_KEY', "")
RAWCHAT_KEY = os.getenv('AUC_RAWCHAT_KEY', "")
DISALLOWED_USERNAMES = (os.getenv('AUC_DISALLOWED_USERNAMES') or "").split("|")
DISALLOWED_WORDS = (os.getenv('AUC_DISALLOWED_WORDS') or "").split("|")


userdb = sqlite3.connect("users.db", check_same_thread=False)
dbcursor = userdb.cursor()

dbcursor.execute("CREATE TABLE IF NOT EXISTS users (uname TEXT, hashedpw BLOB, ip TEXT, known BOOL)")
dbcursor.execute("CREATE TABLE IF NOT EXISTS bannedusers (uname TEXT, reason TEXT)")
dbcursor.execute("CREATE TABLE IF NOT EXISTS bannedips (ip TEXT, reason TEXT)")
dbcursor.execute("CREATE TABLE IF NOT EXISTS usertags (uname TEXT, tag TEXT)")
dbcursor.execute("CREATE TABLE IF NOT EXISTS admins (uname TEXT, type TEXT)")
userdb.commit()

if not os.path.exists("maintenanceMode_Active.conf"):
    with open("maintenanceMode_Active.conf", "w") as f:
        f.write('False')
with open("maintenanceMode_Active.conf") as f:
    if f.read().strip() == 'False':
        maintenance = False
    else:
        maintenance = True
# virt u put this globalization here and its horrifying (-orstando)
# global userCount
userCount = 0

# -- TCP Sockets --
tcp_clients = []

def broadcast(message):
    for client in tcp_clients[:]:
        try:
            client.sendall(message.encode('utf-8'))
        except:
            global userCount
            userCount -= 1
            tcp_clients.remove(client)
            
    socketio.emit('message', message)

def systembroadcast(message):
    for client in tcp_clients[:]:
        try:
            client.sendall("(Server) *[SYSTEM]*: ".encode('utf-8') + message.encode('utf-8'))
        except:
            tcp_clients.remove(client)
            
    socketio.emit('message', message)

def handle_tcp_client(client_socket):
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

def start_tcp_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', TCP_PORT))
    server.listen(5)
    print("AuroraTCP running on port 4040")

    while True:
        client_sock, addr = server.accept()
        print("Client connected through TCP")
        tcp_clients.append(client_sock)
        global userCount
        userCount += 1
        t = threading.Thread(target=handle_tcp_client, args=(client_sock,), daemon=True)
        t.start()

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

socketio.start_background_task(start_tcp_server)

# --- Helper Functions ---
def sha256(data):
      sha256Obj = hashlib.sha256(data.encode('utf-8'))
      finalHash = sha256Obj.hexdigest()
      return finalHash

class Client:
      def __init__(self):
            self.username = None
            self.loggedin = False

def checkAdmin(user):
   dbcursor.execute("SELECT type FROM admins WHERE uname = ?", (user,))
   if dbcursor.fetchone():
        return True
   return False
def checkStaff(user):
    dbcursor.execute("SELECT type FROM admins WHERE uname = ?", (user,))
    if dbcursor.fetchone()[0] == "staff":
        return True
    return False

def checkBan(type,val):
    if type == "user":
        dbcursor.execute("SELECT 1 FROM bannedusers WHERE uname = ?", (val,))
    elif type == "ip":
        dbcursor.execute("SELECT 1 FROM bannedips WHERE ip = ?", (val,))
    if dbcursor.fetchone():
        return True
    return False

# --- Command Parsing ---

def makeAccount(client, data, ip):
      global dbcursor
      if all(key in data for key in ['username','password']): # Make sure username and password exist
            username = data['username']
            password = data['password']
            if "\\" in username or "/" in username or " " in username or len(username) > USERNAME_MAX_CHARS:
                 print(f"Illegal username: '{username}'")
                 return {'data':'ILLEGAL'}
            if any(item in username for item in DISALLOWED_USERNAMES):
                 print(f"Disallowed username: '{username}'")
                 return {'data':'ILLEGAL'}
            if len(password) > PASSWORD_MAX_CHARS:
                 print("Illegal password, exceeded char limit.")
                 return {'data':'ILLEGAL'}
            exists = dbcursor.execute("SELECT uname FROM users WHERE uname = ?", (username,))
            if not dbcursor.fetchone():
                  hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
                  dbcursor.execute("INSERT INTO users (uname, hashedpw, ip, known) VALUES (?, ?, ?, ?)", (username, hashed, ip, False))
                  userdb.commit()
                  print(f"Account '{username}' created")
                  return {'data':"USR_CREATED"}
            else:
                  return {'data':"USR_IN_USE"}
                  print(f"Account creation attempt when it already existed: '{username}'")

def loginAccount(client,data, ip):
      if all(key in data for key in ['username','password']): # Make sure username and password exist
            username = data['username']
            password = data['password']
            if not checkBan("user",username):
                  dbcursor.execute("SELECT hashedpw FROM users WHERE uname = ?", (username,))
                  try:
                     hashedpw = dbcursor.fetchone()[0]
                  except TypeError:
                     hashedpw = None
                  if hashedpw:
                        if bcrypt.checkpw(password.encode('utf-8'), hashedpw):
                              print(f"User '{username}' logged in with IP '{ip}'")
                              client.username = username
                              client.loggedin = True
                              dbcursor.execute("UPDATE users SET ip = ? WHERE uname = ?", (ip,username))
                              userdb.commit()
                              broadcast(f"*[SYSTEM]*: {username} has joined the chat.\n")
                              return {'data':"LOGIN_OK"}
                        else:
                              print("Invalid password.")
                              return {'data':"LOGIN_WRONG_PASS"}
                  else:
                        print("Account not found.")
                        return {'data':"LOGIN_FAKE_ACC"}
            else:
                 print("you're BANNED. LOSER")
                 return {'data':"BANNED"}

def processMessage(client,data, ip):
      if data['cmd'] == "RAWCHAT":
            if data['rawkey'] == RAWCHAT_KEY:
                broadcast(f"{data['content']}\n")
                return {'data':"MSG_SENT"}
                print(f"Message sent with RAWCHAT by IP '{ip}': '{data['content']}'")
            else:
                print(f"IP '{ip}' tried to utilize RAWCHAT without the key.")
                return {'data':"INVALID_KEY"}
      else:
          if (client.loggedin):
                if (len(data['platform']) > 30):
                     return {'data':"ILLEGAL"}

                if checkBan("user",client.username):
                     print(f"A banned user '{client.username}' tried to send a message.")
                     return {'data':"BANNED"}
                if checkBan("ip",ip):
                    print(f"A banned IP '{ip}' tried to send a message.")
                    return {'data':"BANNED"}
    
                if data['cmd'] == "CHAT":
                      typeIdentifier = "<>"
                elif data['cmd'] == "BOTCHAT":
                      typeIdentifier = "[]"
                elif data['cmd'] == "INTCHAT":
                      typeIdentifier = "{}"
                tag = " "
                dbcursor.execute("SELECT tag FROM usertags WHERE uname = ?", (client.username,))
                try:
                    tag = dbcursor.fetchone()[0]
                except TypeError:
                    pass
                if tag != " ":
                    tag = f" ~{tag.strip()}~ "
                elif checkAdmin(client.username):
                      tag = " ~Moderator~ "
                usernameWithIdentifier = f"({data['platform']}){tag}{typeIdentifier[0]}{client.username}{typeIdentifier[1]}"
                
                censored_msg = profanity.censor(data['content'].strip(), '*')
                censored_msg = repr(censored_msg).strip("'")
                if not checkAdmin(client.username):
                  now = int(time.time() * 1000)
                  last_msg = rate_limit.get(client, 0)
                  if now - last_msg < RATE_LIMIT_MS:
                        return {'data':"SPAM",'limit':str(RATE_LIMIT_MS)}
                  rate_limit[client] = now

                if len(censored_msg) > MAX_MESSAGE_LENGTH:
                      return {'data':"TOOLONG",'limit':str(MAX_MESSAGE_LENGTH)}
                if censored_msg.startswith("/ban ip "): # redact ips
                    censored_msg == "/ban ip [redacted]"
                if censored_msg.startswith("/unban ip "):
                    censored_msg == "/unban ip [redacted]"
                if maintenance:
                    if checkAdmin(client.username):
                        broadcast(f"{usernameWithIdentifier}: {censored_msg}\n")
                        cmdResult = syscmd.checkCmd(client.username,data['content'],broadcast,userdb,dbcursor)
                        print(f"Message sent from IP '{ip}' during maintenance mode: '{usernameWithIdentifier}: {censored_msg}'")
                    else:
                        print(f"Message from IP '{ip}' could not send due to server being in maintenance mode: '{usernameWithIdentifier}: {censored_msg}'")
                        return {'data':"MAINTENANCE_MODE"}
                else:
                    broadcast(f"{usernameWithIdentifier}: {censored_msg}\n")
                    cmdResult = syscmd.checkCmd(client.username,data['content'],broadcast,userdb,dbcursor)
                    print(f"Message sent from IP '{ip}': '{usernameWithIdentifier}: {censored_msg}'")
                return {'data':"MSG_SENT"}
          else:
                return {'data':"NO_LOGIN"}

# --- Client Handling ---
def handleClient(ip, data):
      if not checkBan("ip",ip):
            client = Client()
            now_ms = int(time.time() * 1000)
            last_connection = connection_times.get(ip, 0)
            if now_ms - last_connection < RATE_LIMIT_MS:
                  print(f"Too many connections at once from IP '{ip}'")
                  return
            connection_times[ip] = now_ms
            clients[ip] = client
            if not LATEST_VERSION in data['version']:
                  print(f"Connection established with an outdated client from IP '{ip}'.")
                  return {'data':"CONNECT_OK", 'info':"OUTDATED"}
            if LATEST_VERSION in data['version']:
                 print(f"Client connection established from IP '{ip}'.")
                 return {'data':"CONNECT_OK"}
      else:
            print(f"A banned IP tried to connect: '{ip}'")
            return {'data':"BANNED"}

# remove trailing slash (https://stackoverflow.com/a/40365514)
app.url_map.strict_slashes = False
@app.before_request
def clear_trailing():
    rp = request.path
    if rp != '/' and rp.endswith('/'):
        return redirect(rp[:-1])

@app.route('/rules')
def getRules():
    return "rules"
@app.route('/rules/silly')
def sillyRules():
    return "silly rules"
@app.route('/faq')
def getFaq():
    return "faq"
@app.route('/changelog')
def getChangelog():
    return "changelog"

@app.route('/api')
def error405():
    print(f"IP '{request.remote_addr}' accessed the API without using POST.")
    return "Please use POST instead.", 405

@app.route('/')
def rootRedirect():
      return redirect('/api')

# --- Main Server Logic ---
@app.route('/api', methods=['POST'])
def process_request():
    request_json = request.get_json(silent=True)
    if not request_json:
      print(request.data)
      return {'data': 'NO_JSON'}, 400
    if request_json['cmd'] == "CONNECT":
        response = handleClient(request.remote_addr, request_json)
    elif request_json['cmd'] == "MAKEACC":
        response = makeAccount(clients[request.remote_addr], request_json, request.remote_addr)
    elif request_json['cmd'] == "LOGINACC":
        response = loginAccount(clients[request.remote_addr], request_json, request.remote_addr)
    elif request_json['cmd'] in ["CHAT", "BOTCHAT", "INTCHAT", "RAWCHAT"]:
        response = processMessage(clients[request.remote_addr], request_json, request.remote_addr)
    else:
        print("Command not recognized.")
        response = {'data': "BADCMD"}
    return response

# Grab auroraweb
@app.route("/web")
def auoraweb():
    return render_template('auroraweb.html', version=LATEST_VERSION)

@app.route('/stats')
def getStats():
    dbcursor.execute("SELECT COUNT(*) FROM users")
    userCount = dbcursor.fetchone()[0]
    dbcursor.execute("SELECT COUNT(*) FROM bannedusers")
    bannedUserCount = dbcursor.fetchone()[0]
    dbcursor.execute("SELECT COUNT(*) FROM bannedips")
    bannedIpCount = dbcursor.fetchone()[0]
    dbcursor.execute("SELECT COUNT(*) FROM admins")
    adminCount = dbcursor.fetchone()[0]
    return f'''
        <p>Stats</p><br>
        <p>Users: {str(userCount)}</p>
        <p>Banned users: {str(bannedUserCount)}</p>
        <p>Banned IPs: {str(bannedIpCount)}</p>
        <p>Admins: {str(adminCount)}</p>
    '''

# --- Admin Panel ---
@app.route('/style.css', methods=['GET'])
def getCss():
    return '''
    <style>
        a {color:blue;}
        a:visited{color:blue;}
    </style>
    '''

@app.route('/admin/login', methods=['GET','POST'])
def admin_login():
    if request.method == 'POST':
        dbcursor.execute("SELECT type FROM admins WHERE uname = ?", (request.form['username'],))
        admintype = dbcursor.fetchone()[0]
        if admintype:
            dbcursor.execute("SELECT hashedpw FROM users WHERE uname = ?", (request.form['username'],))
            try:
                stored_hash = dbcursor.fetchone()[0]
            except TypeError:
                stored_hash = ""
            if bcrypt.checkpw(request.form['password'].encode('utf-8'), stored_hash):
                if admintype == "staff":
                    session['staff'] = True
                session['admin'] = True
                return redirect('/admin')
        return 'Invalid username or password', 401
    return '''
    <form method="POST">
        <input type="text" name="username" placeholder="Username" required>
        <input type="password" name="password" placeholder="Password" required>
        <button type="submit">Login</button>
    </form>
    '''

@app.route('/admin')
def admin():
    if not session.get('admin'):
        return redirect('/admin/login')
    result = '''
        <link rel='stylesheet' href='/style.css'>
        <p>Admin Panel</p>
        <a href="/admin/ban">Ban/unban user or ip</a><br>
        <a href="/admin/banipfromuname">Ban ip based on username</a><br>
        <a href="/admin/managetags">Tag management</a><br>
        <a href="/admin/stats">Statistics</a><br>
    '''
    if session.get('staff'):
        result = result + "<a href='/staff'>Staff Panel</a>"
    return result

@app.route('/admin/ban', methods=['GET','POST'])
def ban_user():
    if not session.get('admin'):
        return 'Unauthorized', 403
    if request.method == "POST":
        value = request.form['value']
        reason = request.form['reason']
        bantype = request.form['type'] # user / ip
        mode = request.form['mode'] # ban / unban
        if bantype == 'user':
            tableName = 'bannedusers'
            bantype = 'uname'
        elif bantype == 'ip':
            tableName = 'bannedips'
        if mode == 'ban':
            dbcursor.execute(f"INSERT INTO {tableName} ({bantype},reason) VALUES (?,?)", (value,reason))
        elif mode == 'unban':
            dbcursor.execute(f"DELETE FROM {tableName} WHERE {bantype} = ?", (value,))
        userdb.commit()
        return f"<link rel='stylesheet' href='/style.css'><p>{request.form['mode'].title()} successful.</p><a href='/admin'>Back to admin panel</a>"
    return '''
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
    '''

@app.route('/admin/banipfromuname', methods=['GET','POST'])
def banIpFromUsername():
    if not session.get('admin'):
        return 'Unauthorized', 403
    if request.method == 'POST':
        dbcursor.execute("SELECT ip FROM users WHERE uname = ?", (request.form['username'],))
        ip = dbcursor.fetchone()[0]
        if request.form['mode'] == 'ban':
            dbcursor.execute(f"INSERT INTO bannedips (ip,reason) VALUES (?,?)", (ip,request.form['reason']))
        elif request.form['mode'] == 'unban':
            dbcursor.execute(f"DELETE FROM bannedips WHERE ip = ?", (ip,))
        userdb.commit()
        return f"<link rel='stylesheet' href='/style.css'><p>IP successfully {request.form['mode']}ned.</p><a href='/admin'>Back to admin panel</a>"
    else:
        return '''
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
        '''

@app.route('/admin/managetags', methods=['GET','POST'])
def manageTags():
    if not session.get('admin'):
        return "Unauthorized", 403
    if request.method == "POST":
        if request.form['mode'] == "add":
            dbcursor.execute("INSERT INTO usertags (uname,tag) VALUES (?,?)", (request.form['username'],request.form['tag']))
        elif request.form['mode'] == "remove":
            dbcursor.execute("DELETE FROM usertags WHERE uname = ?", (request.form['username'],))
        userdb.commit()
        return f"<link rel='stylesheet' href='/style.css'><p>Tag {request.form['mode']}ed.<p><a href='/admin'>Back to admin panel</a>"
    return '''
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
    '''

# --- Staff Panel ---
@app.route('/staff')
def staff():
    if not session.get('staff'):
        return "Unauthorized", 403
    return '''
        <link rel='stylesheet' href='/style.css'>
        <p>Staff Panel</p>
        <a href="/staff/manageadmins">Admin/staff management</a><br>
        <a href="/staff/getip">Get an IP based on username</a><br>
        <a href="/staff/managedb">Database management</a><br>
        <a href="/staff/maintenance">Toggle maintenance mode</a><br>
        <a href="/admin">Return to admin panel</a>
    '''

@app.route('/staff/manageadmins', methods=['GET','POST'])
def manageAdmins():
    if request.method == 'POST':
        if request.form['mode'] == "add":
            dbcursor.execute("INSERT INTO admins (uname,type) VALUES (?,?)", (request.form['username'],request.form['type']))
        elif request.form['mode'] == "remove":
            if request.form['type'] == "admin":
                dbcursor.execute("DELETE FROM admins WHERE uname = ?", (request.form['username'],))
            elif request.form['type'] == "staff":
                    dbcursor.execute("UPDATE admins SET type = 'admin' WHERE uname = ?", (request.form['username'],))
        userdb.commit()
        return f"<link rel='stylesheet' href='/style.css'><p>{request.form['type'].title()} successfully {request.form['mode']}ed.</p><a href='/staff'>Back to staff panel</a>"
    return '''
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
    '''

@app.route('/staff/getip', methods=['GET','POST'])
def getIp():
    if request.method == 'POST':
        dbcursor.execute("SELECT ip FROM users WHERE uname = ?", (request.form['username'],))
        result = dbcursor.fetchone()[0]
        return f"<link rel='stylesheet' href='/style.css'><p>IP of {request.form['username']}: {result}</p><a href='/staff'>Back to staff panel</a>"
    return '''
        <link rel='stylesheet' href='/style.css'>
        <form method="POST">
            <input name="username" placeholder="Username">
            <input type="submit" value="Submit">
        </form>
        <a href='/staff'>Back to staff panel</a>
    '''

@app.route('/staff/managedb', methods=['GET','POST'])
def manageDb():
    if request.method == 'POST':
        dbcursor.execute(request.form['query'], ())
        result = str(dbcursor.fetchall())
        userdb.commit()
        return f"<link rel='stylesheet' href='/style.css'><p>Result: {result}</p><a href='/staff'>Back to staff panel</a>"
    return '''
        <link rel='stylesheet' href='/style.css'>
        <form method="POST">
            <input name="query" placeholder="Query">
            <input type="submit" value="Submit">
        </form>
        <a href='/staff'>Back to staff panel</a>
    '''

@app.route('/staff/maintenance', methods=['GET','POST'])
def maintenanceMode():
    global maintenance
    if request.method == 'POST':
        with open("maintenanceMode_Active.conf", "r+") as f:
            if f.read().strip() == 'True':
                f.seek(0)
                f.truncate()
                f.write('False')
                maintenance = False
                result = 'de'
            else:
                f.seek(0)
                f.truncate()
                f.write('True')
                maintenance = True
                result = ''
            return f"<link rel='stylesheet' href='/style.css'><p>Maintenance mode {result}activated.</p><a href='/staff'>Back to staff panel</a>"
    else:
        if maintenance:
            status = 'on'
        else:
            status = 'off'
        return f"<link rel='stylesheet' href='/style.css'><p>Maintenance mode is currently {status}.</p><form method='POST'><input type='submit' value='Toggle'></form><a href='/staff'>Back to staff panel</a>"


@socketio.on('connect')
def handle_connect():
    print("WS Connection Established.")
    socketio.emit('message', 'Connected!')


if __name__ == "__main__":
      socketio.run(app, host="0.0.0.0", port=HTTP_PORT, use_reloader=False)
