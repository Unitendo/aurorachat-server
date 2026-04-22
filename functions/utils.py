# Utility functions
import hashlib

def sha256(data):
    sha256Obj = hashlib.sha256(data.encode("utf-8"))
    finalHash = sha256Obj.hexdigest()
    return finalHash