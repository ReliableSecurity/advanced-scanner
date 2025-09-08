#!/usr/bin/env python3
from Crypto.Cipher import AES

# Ключи из оригинального скрипта
STATIC_KEY = b'0123456789abcdef0123456789abcdef'
STATIC_IV = b'fedcba9876543210'

def decrypt_file(encrypted_file_path):
    try:
        with open(encrypted_file_path, 'rb') as f:
            ciphertext = f.read()
        
        cipher = AES.new(STATIC_KEY, AES.MODE_CBC, STATIC_IV)
        padded_plaintext = cipher.decrypt(ciphertext)
        
        # Remove padding
        padding_length = padded_plaintext[-1]
        plaintext = padded_plaintext[:-padding_length]
        
        return plaintext.decode('utf-8', errors='ignore')
        
    except Exception as e:
        return f"Error: {str(e)}"

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 decrypt.py <encrypted_file>")
        sys.exit(1)
    
    result = decrypt_file(sys.argv[1])
    print(result)
