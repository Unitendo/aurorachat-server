# Account migration from files -> SQL

import sqlite3
import os

userdb = sqlite3.connect("users.db", check_same_thread=False)
dbcursor = userdb.cursor()

dbcursor.execute("CREATE TABLE IF NOT EXISTS users (uname TEXT, hashedpw BLOB, ip TEXT, known BOOL)")
dbcursor.execute("CREATE TABLE IF NOT EXISTS bannedusers (uname TEXT, reason TEXT)")
dbcursor.execute("CREATE TABLE IF NOT EXISTS bannedips (ip TEXT, reason TEXT)")
dbcursor.execute("CREATE TABLE IF NOT EXISTS usertags (uname TEXT, tag TEXT)")
dbcursor.execute("CREATE TABLE IF NOT EXISTS admins (uname TEXT, type TEXT)")
userdb.commit()

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ACCOUNT_DIR = os.path.join(SCRIPT_DIR, "accounts")
BANNEDUSR_DIR = os.path.join(SCRIPT_DIR, "bannedusers")
ACCOUNTIPS_DIR = os.path.join(SCRIPT_DIR, "accountips")
BANNEDIP_DIR = os.path.join(SCRIPT_DIR, "bannedips")
ADMIN_DIR = os.path.join(SCRIPT_DIR, "admins")
KNOWNUSR_DIR = os.path.join(SCRIPT_DIR, "knownusers")
TAG_DIR = os.path.join(SCRIPT_DIR, "usertags")

for file in os.listdir(ACCOUNT_DIR):
    filename = os.fsdecode(file)
    if os.path.isfile(os.path.join(ACCOUNT_DIR,file)):
        with open(os.path.join(ACCOUNT_DIR,file),"rb") as f:
            if os.path.exists(os.path.join(ACCOUNTIPS_DIR,filename)):
                with open(os.path.join(ACCOUNTIPS_DIR,filename)) as f2:
                    print(f"migrated {filename}")
                    dbcursor.execute("INSERT INTO users (uname, hashedpw, ip, known) VALUES (?, ?, ?, ?)", (filename, f.read(), f2.read(), os.path.exists(os.path.join(KNOWNUSR_DIR,filename))))
            else:
                print(f"{filename}: no ip")
                dbcursor.execute("INSERT INTO users (uname, hashedpw, ip, known) VALUES (?, ?, ?, ?)", (filename, f.read(), "unknownip", os.path.exists(os.path.join(KNOWNUSR_DIR,filename))))
for file in os.listdir(BANNEDUSR_DIR):
    filename = os.fsdecode(file)
    with open(os.path.join(BANNEDUSR_DIR,file)) as f:
            dbcursor.execute("INSERT INTO bannedusers (uname, reason) VALUES (?, ?)", (filename, f.read()))
    print(f"migrated {filename}")
for file in os.listdir(BANNEDIP_DIR):
    filename = os.fsdecode(file)
    with open(os.path.join(BANNEDIP_DIR,file)) as f:
            dbcursor.execute("INSERT INTO bannedips (ip, reason) VALUES (?, ?)", (filename, f.read()))
    print(f"migrated {filename}")
for file in os.listdir(TAG_DIR):
    filename = os.fsdecode(file)
    with open(os.path.join(TAG_DIR,file)) as f:
            dbcursor.execute("INSERT INTO usertags (uname, tag) VALUES (?, ?)", (filename, f.read()))
    print(f"migrated {filename}")
for file in os.listdir(ADMIN_DIR):
    filename = os.fsdecode(file)
    with open(os.path.join(ADMIN_DIR,file)) as f:
            dbcursor.execute("INSERT INTO admins (uname, type) VALUES (?, ?)", (filename, "admin"))
    print(f"migrated {filename}")
userdb.commit()
