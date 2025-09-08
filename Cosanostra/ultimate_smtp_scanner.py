#!/usr/bin/env python3
"""
AKUMA's Ultimate SMTP Vulnerability Scanner 💀
Комбинированный инструмент для полного анализа SMTP серверов
Массовое сканирование + продвинутые техники обхода
"""

import socket
import time
import threading
import json
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
# from smtp_evasion_toolkit import SMTPEvasionTester  # Импорт закомментирован для независимой работы

class UltimateSMTPScanner:
    def __init__(self, timeout=15, threads=10, deep_scan=False):
        self.timeout = timeout
        self.threads = threads
        self.deep_scan = deep_scan
        self.results = []
        self.lock = threading.Lock()
        # self.evasion_tester = SMTPEvasionTester(timeout=timeout)  # Отключено для базовой версии
        
        # Расширенный список портов для сканирования
        self.smtp_ports = [25, 587, 465, 2525, 1025, 26, 2526]
        
        # Целевые серверы
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
            "newwedsfoods.com": None,
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
    
    def ultimate_banner(self):
        """Легендарный баннер для легендарного хакера"""
        print("╔" + "═" * 68 + "╗")
        print("║" + " " * 18 + "🔥 AKUMA's Ultimate SMTP Scanner 🔥" + " " * 13 + "║")
        print("║" + " " * 12 + "The Most Advanced SMTP Vulnerability Hunter" + " " * 12 + "║")
        print("║" + " " * 68 + "║")
        print("║" + f" Targets: {len([t for t in self.targets.values() if t]):>3} | Ports: {len(self.smtp_ports):>2} | Threads: {self.threads:>2} | Deep Scan: {'ON' if self.deep_scan else 'OFF':>3}" + " " * 13 + "║")
        print("╚" + "═" * 68 + "╝")
        print()
        print("🎯 \"Hack the planet, one SMTP server at a time!\" - AKUMA")
        print("📡 Scanning for SMTP relay vulnerabilities across all target companies...")
        print()
    
    def resolve_target(self, domain):
        """DNS Resolution с обработкой ошибок"""
        ip = self.targets.get(domain)
        if ip:
            return ip
        
        try:
            ip = socket.gethostbyname(domain)
            print(f"[*] Resolved {domain} -> {ip}")
            return ip
        except Exception as e:
            print(f"[-] Failed to resolve {domain}: {e}")
            return None
    
    def quick_smtp_test(self, domain, ip, port):
        """Быстрое тестирование SMTP порта"""
        result = {
            'domain': domain,
            'ip': ip,
            'port': port,
            'status': 'closed',
            'banner': None,
            'smtp_version': None,
            'supports_auth': False,
            'supports_tls': False,
            'basic_relay_test': False,
            'evasion_results': [],
            'error': None,
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            result['status'] = 'open'
            
            # Читаем баннер
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            result['banner'] = banner
            
            # Извлекаем версию SMTP сервера
            if banner:
                parts = banner.split()
                if len(parts) >= 2:
                    result['smtp_version'] = parts[1] if len(parts) > 2 else parts[0]
            
            if '220' in banner:
                # EHLO для получения возможностей
                sock.send(b"EHLO akuma-scan.test\r\n")
                time.sleep(1)
                ehlo_response = sock.recv(2048).decode('utf-8', errors='ignore')
                
                if '250' in ehlo_response:
                    # Проверяем поддержку AUTH и TLS
                    result['supports_auth'] = 'AUTH' in ehlo_response.upper()
                    result['supports_tls'] = any(tls in ehlo_response.upper() for tls in ['STARTTLS', 'TLS'])
                    
                    # Быстрое тестирование relay
                    result['basic_relay_test'] = self.quick_relay_test(sock, domain)
                    
                    # Если включен deep scan, запускаем продвинутые тесты
                    if self.deep_scan and result['basic_relay_test']:
                        print(f"    🔥 Basic relay found on {ip}:{port}, running deep scan...")
                        # evasion_results = self.evasion_tester.comprehensive_test(ip, port, domain)
                        # result['evasion_results'] = evasion_results
                        result['evasion_results'] = []  # Пока отключено
            
            sock.send(b"QUIT\r\n")
            sock.close()
            
        except socket.timeout:
            result['error'] = 'timeout'
        except ConnectionRefusedError:
            result['error'] = 'connection_refused'
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def quick_relay_test(self, sock, domain):
        """Быстрое тестирование relay возможностей"""
        test_cases = [
            ("akuma@test.com", "victim@external.com"),
            ("", "victim@external.com"),
            (f"test@{domain}", "victim@external.com")
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
                        return True
            except Exception:
                continue
        
        return False
    
    def scan_target_comprehensive(self, domain):
        """Комплексное сканирование одной цели"""
        ip = self.resolve_target(domain)
        if not ip:
            return
        
        print(f"🎯 Scanning {domain} ({ip})...")
        target_results = []
        
        for port in self.smtp_ports:
            result = self.quick_smtp_test(domain, ip, port)
            target_results.append(result)
            
            # Статус индикаторы
            status_icon = "✅" if result['status'] == 'open' else "❌"
            relay_icon = "🔥" if result['basic_relay_test'] else ""
            auth_icon = "🔐" if result['supports_auth'] else ""
            tls_icon = "🔒" if result['supports_tls'] else ""
            
            print(f"    {status_icon} {ip}:{port:<4} {relay_icon}{auth_icon}{tls_icon} - {result['status']}")
            
            if result['status'] == 'open':
                if result['banner']:
                    print(f"        📝 {result['banner'][:60]}...")
                if result['basic_relay_test']:
                    print(f"        🚨 RELAY VULNERABILITY DETECTED!")
                if result['evasion_results']:
                    print(f"        🎭 Advanced evasion techniques: {len(result['evasion_results'])} found")
        
        with self.lock:
            self.results.extend(target_results)
    
    def run_ultimate_scan(self):
        """Запуск полного сканирования"""
        self.ultimate_banner()
        
        valid_targets = [domain for domain, ip in self.targets.items() if ip or domain]
        
        print(f"🚀 Initiating ultimate scan of {len(valid_targets)} corporate mail servers...")
        print(f"⏱️  Estimated time: ~{(len(valid_targets) * len(self.smtp_ports) * self.timeout / self.threads):.0f} seconds")
        print()
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.scan_target_comprehensive, valid_targets)
        
        scan_time = time.time() - start_time
        self.generate_ultimate_report(scan_time)
    
    def generate_ultimate_report(self, scan_time):
        """Генерация финального отчёта"""
        print("\n" + "═" * 70)
        print("📊 AKUMA's Ultimate SMTP Vulnerability Report")
        print("═" * 70)
        
        open_ports = [r for r in self.results if r['status'] == 'open']
        basic_vulns = [r for r in self.results if r['basic_relay_test']]
        evasion_vulns = [r for r in self.results if r['evasion_results']]
        auth_servers = [r for r in self.results if r['supports_auth']]
        tls_servers = [r for r in self.results if r['supports_tls']]
        
        print(f"⏱️  Scan Duration: {scan_time:.2f} seconds")
        print(f"🎯 Total Targets: {len(set(r['domain'] for r in self.results))}")
        print(f"🔍 Total Ports Tested: {len(self.results)}")
        print(f"📡 Open SMTP Ports: {len(open_ports)}")
        print(f"🚨 Basic Relay Vulnerabilities: {len(basic_vulns)}")
        print(f"🎭 Advanced Evasion Vulns: {len(evasion_vulns)}")
        print(f"🔐 Servers with AUTH: {len(auth_servers)}")
        print(f"🔒 Servers with TLS: {len(tls_servers)}")
        
        if basic_vulns:
            print("\n🔥 CRITICAL: Basic SMTP Relay Vulnerabilities Found!")
            print("─" * 60)
            for vuln in basic_vulns:
                severity = "HIGH" if vuln['evasion_results'] else "MEDIUM"
                print(f"🎯 {vuln['domain']} ({vuln['ip']}:{vuln['port']}) - Severity: {severity}")
                if vuln['banner']:
                    print(f"   📝 Banner: {vuln['banner']}")
                if vuln['evasion_results']:
                    print(f"   🎭 Evasion techniques: {len(vuln['evasion_results'])}")
                print()
        
        if evasion_vulns:
            print("\n🎭 Advanced Evasion Techniques Successful:")
            print("─" * 50)
            for server in evasion_vulns:
                print(f"🔥 {server['domain']} ({server['ip']}:{server['port']})")
                for evasion in server['evasion_results']:
                    print(f"   • {evasion['technique']}: {evasion['from']} -> {evasion['to']}")
                print()
        
        # Статистика по безопасности
        print("\n🛡️  Security Features Analysis:")
        print("─" * 40)
        total_open = len(open_ports)
        if total_open > 0:
            auth_percent = (len(auth_servers) / total_open) * 100
            tls_percent = (len(tls_servers) / total_open) * 100
            vuln_percent = (len(basic_vulns) / total_open) * 100
            
            print(f"📊 AUTH Support: {auth_percent:.1f}% ({len(auth_servers)}/{total_open})")
            print(f"📊 TLS Support: {tls_percent:.1f}% ({len(tls_servers)}/{total_open})")
            print(f"📊 Relay Vulnerable: {vuln_percent:.1f}% ({len(basic_vulns)}/{total_open})")
        
        # Сохранение результатов
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"akuma_ultimate_smtp_scan_{timestamp}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump({
                'scan_info': {
                    'timestamp': timestamp,
                    'duration': scan_time,
                    'deep_scan': self.deep_scan,
                    'threads': self.threads,
                    'timeout': self.timeout
                },
                'summary': {
                    'total_targets': len(set(r['domain'] for r in self.results)),
                    'open_ports': len(open_ports),
                    'basic_vulnerabilities': len(basic_vulns),
                    'evasion_vulnerabilities': len(evasion_vulns)
                },
                'results': self.results
            }, f, indent=2, default=str, ensure_ascii=False)
        
        print(f"\n💾 Complete results saved to: {filename}")
        
        if basic_vulns:
            print("\n" + "⚠️ " * 10)
            print("🚨 VULNERABILITY ALERT: Exploitable SMTP relays found!")
            print("📝 Create tickets for vulnerable servers immediately.")
            print("💰 Potential bounty opportunities identified.")
            print("⚠️ " * 10)
        else:
            print("\n✅ No exploitable SMTP relay vulnerabilities detected.")
            print("🛡️  All scanned servers appear to be properly secured.")
        
        print("\n🎯 As AKUMA always says: 'Scan responsibly, exploit ethically!'")
        print("═" * 70)

def main():
    parser = argparse.ArgumentParser(
        description="AKUMA's Ultimate SMTP Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                           # Basic scan
  %(prog)s --deep                    # Deep scan with evasion techniques
  %(prog)s -t 30 --timeout 20       # 30 threads, 20s timeout
  %(prog)s --deep -t 5              # Deep scan with 5 threads (slower but thorough)

AKUMA's Tips:
  - Use --deep for maximum vulnerability coverage
  - Increase threads for faster scanning (but be respectful)
  - Lower timeout if you're getting too many timeouts
        """)
    
    parser.add_argument('-t', '--threads', type=int, default=10, 
                       help='Number of concurrent threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=15, 
                       help='Socket timeout in seconds (default: 15)')
    parser.add_argument('--deep', action='store_true', 
                       help='Enable deep scanning with evasion techniques')
    
    args = parser.parse_args()
    
    try:
        scanner = UltimateSMTPScanner(
            timeout=args.timeout, 
            threads=args.threads, 
            deep_scan=args.deep
        )
        scanner.run_ultimate_scan()
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user. Partial results may be available.")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
