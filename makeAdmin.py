# make an account admin (if you dont yet have a staff account that can access admin management)

username = input("Enter username: ")
typeInput = input("Type (1=admin, 2=staff): ")
if typeInput == "1":
    type = "admin"
elif typeInput == "2":
    type = "staff"
import sqlite3
userdb = sqlite3.connect("users.db", check_same_thread=False)
dbcursor = userdb.cursor()
dbcursor.execute("INSERT INTO admins (uname,type) VALUES (?,?)", (username,type))
userdb.commit()
