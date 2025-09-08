#!/usr/bin/env python3
"""
AKUMA's Quick SMTP Test 🔥
Быстрая проверка одного SMTP сервера для демонстрации
"""

import socket
import time

def quick_smtp_check(host, port=25):
    """Быстрая проверка SMTP сервера"""
    print(f"🎯 Testing {host}:{port}...")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((host, port))
        
        # Читаем баннер
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        print(f"✅ Connected! Banner: {banner}")
        
        # EHLO
        sock.send(b"EHLO test.com\r\n")
        time.sleep(1)
        ehlo_response = sock.recv(1024).decode('utf-8', errors='ignore')
        print(f"📝 EHLO Response: {ehlo_response.strip()}")
        
        # Тест relay
        if '250' in ehlo_response:
            print("🔍 Testing relay capabilities...")
            
            # MAIL FROM
            sock.send(b"MAIL FROM:<test@external.com>\r\n")
            time.sleep(0.5)
            mail_response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            if '250' in mail_response:
                print("✅ MAIL FROM accepted")
                
                # RCPT TO
                sock.send(b"RCPT TO:<victim@external.com>\r\n")
                time.sleep(0.5)
                rcpt_response = sock.recv(1024).decode('utf-8', errors='ignore')
                
                if '250' in rcpt_response:
                    print("🚨 VULNERABILITY: Server accepts external relay!")
                    print(f"📝 Response: {rcpt_response.strip()}")
                else:
                    print("✅ Server properly rejects external relay")
                    print(f"📝 Response: {rcpt_response.strip()}")
            else:
                print("❌ MAIL FROM rejected")
        
        sock.send(b"QUIT\r\n")
        sock.close()
        
    except socket.timeout:
        print("❌ Connection timeout")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    # Тест на одном из серверов
    quick_smtp_check("medel.com", 25)
    print()
    quick_smtp_check("104.16.4.14", 25)
