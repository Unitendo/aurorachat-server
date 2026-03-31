import os

broadcast = None
msg = None
user = None

def send(msg,prefix="*[SYSTEM]*: "): # Message wrapper
   global broadcast
   broadcast(prefix+msg+"\n")

def info(user,msg):
   send("Press Y to see the rules,")
   send("along with an FAQ and a link to our Discord server.", prefix="")

def welcomeMsg(user, msg, db, cursor):
   cursor.execute("SELECT known FROM users WHERE uname = ?", (user,))
   known = cursor.fetchone()[0]
   if not known:
      cursor.execute("UPDATE users SET known = ? WHERE uname = ?", (True,user))
      db.commit()
      send(f"{user}, type /info if you're new!")

def cmd(cmd,func,args=[],kwargs={}): # Command wrapper
   global user, msg
   if msg.startswith(cmd):
      return func(user, msg, *args, **kwargs)

# Custom commands (other than /ban and /unban) go here
def cmdSetup(userarg,msgarg,broadcastarg,db,cursor):
   global broadcast,msg,user
   broadcast = broadcastarg
   msg = msgarg
   user = userarg

   welcomeMsg(user,msg,db,cursor)

   cmd("/info", info)
