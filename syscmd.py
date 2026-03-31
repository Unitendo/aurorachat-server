import os

msg = None
broadcast = None
sysprefix = "*[SYSTEM]*: "

def send(msg): # Message wrapper
   global sysprefix, broadcast
   broadcast(sysprefix+msg+"\n")

def checkAdmin(user,cursor):
   cursor.execute("SELECT uname FROM admins WHERE uname = ?", (user,))
   if cursor.fetchone():
        return True
   return False

def ban(user,msg,db,cursor):
   if not checkAdmin(user,cursor):
      send("Invalid permissions.")
      return
   parts = msg.split(' ', 3)
   userToBan = parts[2].strip()
   usrOrIp = parts[1].strip()
   if usrOrIp == 'user':
      tableName = 'bannedusers'
      usrOrIp = 'uname'
   elif usrOrIp == 'ip':
      tableName = 'bannedips'
   else:
      send("Invalid syntax.")
      return
   cursor.execute(f"INSERT INTO {tableName} ({usrOrIp}) VALUES (?)", (userToBan,))
   db.commit()
   if usrOrIp == "ip":
         send("IP banned successfully.")
   else:
         send("User banned successfully.")

def unban(user,msg,db,cursor):
   if not checkAdmin(user,cursor):
      send("Invalid permissions.")
      return
   parts = msg.split(' ', 3)
   userToUnban = parts[2].strip()
   usrOrIp = parts[1].strip()
   if usrOrIp == 'user':
      tableName = 'bannedusers'
      usrOrIp = 'uname'
   elif usrOrIp == 'ip':
      tableName = 'bannedips'
   else:
      send("Invalid syntax.")
      return
   dbcursor.execute(f"DELETE FROM {tableName} WHERE {usrOrIp} = ?", (value,))

def cmd(cmd,callback,args=[],kwargs={}): # Command wrapper
   global msg
   if msg.startswith(cmd):
      return callback(*args, **kwargs)

def checkCmd(user,msgarg,broadcastarg,db,cursor): # add extra imports if needed
   global broadcast, msg
   broadcast = broadcastarg
   msg = msgarg

   cmd("/ban", ban, args=[user,msg,db,cursor])
   cmd("/unban", unban, args=[user,msg,db,cursor])

   import custom_commands
   custom_commands.cmdSetup(user,msg,broadcast,db,cursor)
