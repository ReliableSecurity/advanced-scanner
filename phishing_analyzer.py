#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AKUMA's Ultimate Phishing Log Analyzer
Скрипт для анализа логов фишинга и создания отчёта для руководства

Автор: AKUMA (легендарный хакер)
Версия: 1.0 "Как в старые добрые времена"
"""

import csv
import json
import re
from datetime import datetime
from collections import defaultdict, Counter
from urllib.parse import unquote
import ipaddress
import requests
from time import sleep

class PhishingLogAnalyzer:
    def __init__(self, csv_file_path):
        self.csv_file_path = csv_file_path
        self.click_data = []
        self.creds_data = []
        self.unique_ips = set()
        self.user_agents = []
        self.click_times = []
        self.creds_times = []
        self.payload_data = []
        
    def parse_csv(self):
        """Парсинг CSV файла с логами фишинга"""
        print(f"🔍 Парсим логи из файла: {self.csv_file_path}")
        
        try:
            with open(self.csv_file_path, 'r', encoding='utf-8') as file:
                # Убираем номера строк в начале
                content = file.read().replace('\r', '')
                lines = content.strip().split('\n')
                
                # Пропускаем заголовок
                header_line = lines[0].split('|', 1)[1] if '|' in lines[0] else lines[0]
                
                for i, line in enumerate(lines[1:], 2):
                    try:
                        # Удаляем номер строки в начале
                        if '|' in line:
                            clean_line = line.split('|', 1)[1]
                        else:
                            clean_line = line
                            
                        # Парсим CSV строку
                        parts = self._parse_csv_line(clean_line)
                        if len(parts) >= 5:
                            campaign_id, email, timestamp, message, details = parts[:5]
                            
                            # Обрабатываем клики и отправку данных
                            if message.strip() == "Clicked Link" and details:
                                parsed_details = self._parse_details(details)
                                if parsed_details:
                                    record = {
                                        'campaign_id': campaign_id,
                                        'email': email,
                                        'timestamp': timestamp,
                                        'message': message,
                                        'ip_address': parsed_details.get('ip_address'),
                                        'user_agent': parsed_details.get('user_agent'),
                                        'payload': parsed_details.get('payload')
                                    }
                                    self.click_data.append(record)
                                    
                                    if record['ip_address']:
                                        self.unique_ips.add(record['ip_address'])
                                    if record['user_agent']:
                                        self.user_agents.append(record['user_agent'])
                                    if record['timestamp']:
                                        self.click_times.append(timestamp)
                            
                            elif message.strip() == "Submitted Data" and details:
                                parsed_details = self._parse_details(details)
                                if parsed_details:
                                    record = {
                                        'campaign_id': campaign_id,
                                        'email': email,
                                        'timestamp': timestamp,
                                        'message': message,
                                        'ip_address': parsed_details.get('ip_address'),
                                        'user_agent': parsed_details.get('user_agent'),
                                        'payload': parsed_details.get('payload'),
                                        'submitted_email': parsed_details.get('submitted_email'),
                                        'submitted_password': parsed_details.get('submitted_password')
                                    }
                                    self.creds_data.append(record)
                                    
                                    if record['ip_address']:
                                        self.unique_ips.add(record['ip_address'])
                                    if record['user_agent']:
                                        self.user_agents.append(record['user_agent'])
                                    if record['timestamp']:
                                        self.creds_times.append(timestamp)
                                        
                    except Exception as e:
                        print(f"⚠️  Ошибка парсинга строки {i}: {e}")
                        continue
                        
        except Exception as e:
            print(f"💥 Ошибка чтения файла: {e}")
            return False
            
        print(f"✅ Успешно распарсено {len(self.click_data)} записей о кликах")
        print(f"🎯 Успешно распарсено {len(self.creds_data)} записей с кредами")
        return True
    
    def _parse_csv_line(self, line):
        """Парсинг CSV строки с учётом escape символов"""
        parts = []
        current_part = ""
        in_quotes = False
        i = 0
        
        while i < len(line):
            char = line[i]
            
            if char == '"' and (i == 0 or line[i-1] != '\\'):
                in_quotes = not in_quotes
            elif char == ',' and not in_quotes:
                parts.append(current_part.strip())
                current_part = ""
                i += 1
                continue
            
            current_part += char
            i += 1
            
        if current_part:
            parts.append(current_part.strip())
            
        return parts
    
    def _parse_details(self, details_str):
        """Парсинг JSON данных из поля details"""
        try:
            # Убираем лишние escape символы и кавычки
            cleaned = details_str.strip('"')
            cleaned = cleaned.replace('""', '"')
            
            # Пытаемся распарсить JSON
            data = json.loads(cleaned)
            
            browser_info = data.get('browser', {})
            payload_info = data.get('payload', {})
            
            result = {
                'ip_address': browser_info.get('address'),
                'user_agent': browser_info.get('user-agent'),
                'payload': payload_info
            }
            
            # Извлекаем креды если есть
            if 'email' in payload_info and payload_info['email']:
                result['submitted_email'] = payload_info['email'][0] if isinstance(payload_info['email'], list) else payload_info['email']
            if 'password' in payload_info and payload_info['password']:
                result['submitted_password'] = payload_info['password'][0] if isinstance(payload_info['password'], list) else payload_info['password']
                
            return result
        except Exception as e:
            # Если JSON не парсится, пытаемся извлечь данные регуляркой
            ip_match = re.search(r'"address":"([^"]+)"', details_str)
            ua_match = re.search(r'"user-agent":"([^"]+)"', details_str)
            email_match = re.search(r'"email":\["([^"]+)"\]', details_str)
            password_match = re.search(r'"password":\["([^"]+)"\]', details_str)
            
            result = {
                'ip_address': ip_match.group(1) if ip_match else None,
                'user_agent': ua_match.group(1) if ua_match else None,
                'payload': {}
            }
            
            if email_match:
                result['submitted_email'] = email_match.group(1)
            if password_match:
                result['submitted_password'] = password_match.group(1)
                
            return result
    
    def analyze_time_patterns(self):
        """Анализ временных паттернов кликов"""
        print("📊 Анализируем временные паттерны...")
        
        hourly_stats = defaultdict(int)
        daily_stats = defaultdict(int)
        
        for timestamp in self.click_times:
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                hour = dt.hour
                day = dt.strftime('%Y-%m-%d')
                
                hourly_stats[hour] += 1
                daily_stats[day] += 1
            except:
                continue
                
        return {
            'hourly_distribution': dict(hourly_stats),
            'daily_distribution': dict(daily_stats),
            'total_clicks': len(self.click_times),
            'peak_hour': max(hourly_stats.items(), key=lambda x: x[1]) if hourly_stats else None,
            'peak_day': max(daily_stats.items(), key=lambda x: x[1]) if daily_stats else None
        }
    
    def analyze_ip_addresses(self):
        """Анализ IP адресов"""
        print("🌍 Анализируем IP адреса...")
        
        ip_stats = Counter()
        network_stats = defaultdict(int)
        suspicious_ips = []
        
        # Объединяем данные кликов и кредов для анализа IP
        all_data = self.click_data + self.creds_data
        
        for record in all_data:
            if record['ip_address']:
                ip = record['ip_address']
                ip_stats[ip] += 1
                
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    # Группируем по /24 сетям
                    if ip_obj.version == 4:
                        network = str(ipaddress.IPv4Network(f"{ip}/24", strict=False))
                        network_stats[network] += 1
                        
                        # Проверяем на подозрительные диапазоны
                        if (ip.startswith('209.222.82.') or  # Много кликов с одной сети
                            ip.startswith('172.253.') or      # Google ranges
                            ip.startswith('35.') or           # Cloud providers
                            ip.startswith('34.')):
                            suspicious_ips.append(ip)
                            
                except:
                    pass
        
        return {
            'unique_ips': len(self.unique_ips),
            'top_ips': dict(ip_stats.most_common(10)),
            'suspicious_ips': list(set(suspicious_ips)),
            'network_distribution': dict(network_stats),
            'repeat_clickers': {ip: count for ip, count in ip_stats.items() if count > 1}
        }
    
    def analyze_user_agents(self):
        """Анализ User-Agent строк"""
        print("🔍 Анализируем User-Agent строки...")
        
        ua_counter = Counter(self.user_agents)
        browsers = defaultdict(int)
        os_counter = defaultdict(int)
        suspicious_ua = []
        
        for ua in self.user_agents:
            # Определяем браузер
            if 'Chrome' in ua:
                browsers['Chrome'] += 1
            elif 'Firefox' in ua:
                browsers['Firefox'] += 1
            elif 'Safari' in ua and 'Chrome' not in ua:
                browsers['Safari'] += 1
            elif 'Edge' in ua:
                browsers['Edge'] += 1
            elif 'MSIE' in ua or 'Trident' in ua:
                browsers['Internet Explorer'] += 1
            else:
                browsers['Other'] += 1
                
            # Определяем ОС
            if 'Windows NT' in ua:
                os_counter['Windows'] += 1
            elif 'Macintosh' in ua or 'Mac OS X' in ua:
                os_counter['macOS'] += 1
            elif 'Linux' in ua:
                os_counter['Linux'] += 1
            elif 'Android' in ua:
                os_counter['Android'] += 1
            elif 'iPhone' in ua or 'iOS' in ua:
                os_counter['iOS'] += 1
            else:
                os_counter['Other'] += 1
                
            # Ищем подозрительные UA
            if (any(word in ua.lower() for word in ['bot', 'crawler', 'spider', 'scraper']) or
                'AntiSpam-Agent' in ua or
                'AppEngine-Google' in ua or
                ua.count('Mozilla') > 1):
                suspicious_ua.append(ua)
        
        return {
            'total_user_agents': len(self.user_agents),
            'unique_user_agents': len(ua_counter),
            'top_user_agents': dict(ua_counter.most_common(5)),
            'browser_distribution': dict(browsers),
            'os_distribution': dict(os_counter),
            'suspicious_user_agents': list(set(suspicious_ua))
        }
    
    def analyze_credentials(self):
        """Анализ полученных учетных данных"""
        print("🎯 Анализируем полученные учетные данные...")
        
        creds_by_ip = defaultdict(list)
        email_domains = Counter()
        password_patterns = {
            'weak': 0,      # простые пароли
            'medium': 0,    # средние
            'strong': 0     # сложные
        }
        
        for record in self.creds_data:
            ip = record.get('ip_address', 'Unknown')
            email = record.get('submitted_email', '')
            password = record.get('submitted_password', '')
            
            creds_by_ip[ip].append({
                'email': email,
                'password': password,
                'timestamp': record.get('timestamp', ''),
                'user_agent': record.get('user_agent', '')
            })
            
            # Анализ доменов
            if '@' in email:
                domain = email.split('@')[1].lower()
                email_domains[domain] += 1
            
            # Анализ сложности паролей
            if password:
                if len(password) < 6 or password.lower() in ['password', '123456', 'qwerty']:
                    password_patterns['weak'] += 1
                elif len(password) < 10 and not any(c.isupper() for c in password):
                    password_patterns['medium'] += 1
                else:
                    password_patterns['strong'] += 1
        
        return {
            'total_credentials': len(self.creds_data),
            'credentials_by_ip': dict(creds_by_ip),
            'email_domains': dict(email_domains.most_common(10)),
            'password_patterns': password_patterns,
            'unique_emails': len(set([r.get('submitted_email', '') for r in self.creds_data if r.get('submitted_email')])),
            'submission_times': self.creds_times
        }
    
    def get_ip_geolocation(self, ip_address):
        """Получение геолокации IP адреса через ip-api.com"""
        try:
            response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data['status'] == 'success':
                    return {
                        'country': data.get('country', 'Unknown'),
                        'city': data.get('city', 'Unknown'),
                        'region': data.get('regionName', 'Unknown'),
                        'isp': data.get('isp', 'Unknown'),
                        'org': data.get('org', 'Unknown'),
                        'lat': data.get('lat', 0),
                        'lon': data.get('lon', 0)
                    }
        except Exception:
            pass
        
        return {
            'country': 'Unknown',
            'city': 'Unknown', 
            'region': 'Unknown',
            'isp': 'Unknown',
            'org': 'Unknown',
            'lat': 0,
            'lon': 0
        }
    
    def analyze_geolocation(self):
        """Анализ географического распределения"""
        print("🗺️  Анализируем географическое распределение...")
        
        country_stats = Counter()
        city_stats = Counter()
        isp_stats = Counter()
        
        creds_locations = []
        
        # Ограничиваем количество запросов к API
        unique_ips = list(self.unique_ips)[:50]  # Берём только топ-50 IP
        
        for i, ip in enumerate(unique_ips):
            if i > 0 and i % 10 == 0:
                print(f"   Обработано {i}/{len(unique_ips)} IP адресов...")
                sleep(1)  # Пауза между запросами
                
            location = self.get_ip_geolocation(ip)
            country_stats[location['country']] += 1
            city_stats[f"{location['city']}, {location['country']}"] += 1
            isp_stats[location['isp']] += 1
            
            # Проверяем есть ли креды с этого IP
            ip_creds = [record for record in self.creds_data if record.get('ip_address') == ip]
            if ip_creds:
                for cred in ip_creds:
                    creds_locations.append({
                        'ip': ip,
                        'location': location,
                        'email': cred.get('submitted_email', ''),
                        'timestamp': cred.get('timestamp', '')
                    })
        
        return {
            'country_distribution': dict(country_stats.most_common(10)),
            'city_distribution': dict(city_stats.most_common(10)),
            'isp_distribution': dict(isp_stats.most_common(10)),
            'credentials_locations': creds_locations
        }
    
    def generate_report(self):
        """Генерация итогового отчёта"""
        print("📋 Генерируем итоговый отчёт...")
        
        time_analysis = self.analyze_time_patterns()
        ip_analysis = self.analyze_ip_addresses()
        ua_analysis = self.analyze_user_agents()
        creds_analysis = self.analyze_credentials()
        geo_analysis = self.analyze_geolocation() if len(self.creds_data) > 0 else None
        
        report = f"""
╔══════════════════════════════════════════════════════════════╗
║                   🎯 ОТЧЁТ ПО ФИШИНГ-ТЕСТИРОВАНИЮ              ║
║                     (анализ результатов)                      ║
╚══════════════════════════════════════════════════════════════╝

📊 ОБЩАЯ СТАТИСТИКА:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• Общее количество кликов: {time_analysis['total_clicks']}
• Полученных учётных записей: {creds_analysis['total_credentials']}
• Уникальных IP адресов: {ip_analysis['unique_ips']}
• Уникальных User-Agent: {ua_analysis['unique_user_agents']}
• Email цель: dmitriyvisotskiydr15061991@gmail.com

⏰ ВРЕМЕННОЙ АНАЛИЗ:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• Период активности: {min(time_analysis['daily_distribution'].keys()) if time_analysis['daily_distribution'] else 'N/A'} - {max(time_analysis['daily_distribution'].keys()) if time_analysis['daily_distribution'] else 'N/A'}
• Пиковый час: {time_analysis['peak_hour'][0] if time_analysis['peak_hour'] else 'N/A'}:00 ({time_analysis['peak_hour'][1] if time_analysis['peak_hour'] else 0} кликов)
• Самый активный день: {time_analysis['peak_day'][0] if time_analysis['peak_day'] else 'N/A'} ({time_analysis['peak_day'][1] if time_analysis['peak_day'] else 0} кликов)

🌍 АНАЛИЗ IP АДРЕСОВ:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• Топ-5 IP адресов по активности:"""
        
        # Добавляем топ IP
        for i, (ip, count) in enumerate(list(ip_analysis['top_ips'].items())[:5], 1):
            report += f"\n  {i}. {ip} - {count} кликов"
        
        report += f"""

• Подозрительные IP (облачные/автоматизированные): {len(ip_analysis['suspicious_ips'])}
• IP с повторными кликами: {len(ip_analysis['repeat_clickers'])}

🔍 АНАЛИЗ БРАУЗЕРОВ:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""

        # Распределение браузеров
        for browser, count in sorted(ua_analysis['browser_distribution'].items(), key=lambda x: x[1], reverse=True):
            percentage = (count / ua_analysis['total_user_agents']) * 100
            report += f"\n• {browser}: {count} ({percentage:.1f}%)"

        report += f"""

🖥️  АНАЛИЗ ОПЕРАЦИОННЫХ СИСТЕМ:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""

        # Распределение ОС
        for os_name, count in sorted(ua_analysis['os_distribution'].items(), key=lambda x: x[1], reverse=True):
            percentage = (count / ua_analysis['total_user_agents']) * 100
            report += f"\n• {os_name}: {count} ({percentage:.1f}%)"

        # Добавляем анализ учётных данных
        if creds_analysis['total_credentials'] > 0:
            report += f"""

🎯 АНАЛИЗ ПОЛУЧЕННЫХ УЧЁТНЫХ ДАННЫХ:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• Всего получено учётных записей: {creds_analysis['total_credentials']}
• Уникальных email адресов: {creds_analysis['unique_emails']}

📧 ТОП EMAIL ДОМЕНОВ:"""
            for domain, count in list(creds_analysis['email_domains'].items())[:5]:
                report += f"\n• {domain}: {count} записей"
            
            report += f"""

🔐 АНАЛИЗ ПАРОЛЕЙ:
• Слабые пароли: {creds_analysis['password_patterns']['weak']} ({(creds_analysis['password_patterns']['weak']/max(1, creds_analysis['total_credentials'])*100):.1f}%)
• Средние пароли: {creds_analysis['password_patterns']['medium']} ({(creds_analysis['password_patterns']['medium']/max(1, creds_analysis['total_credentials'])*100):.1f}%)
• Сложные пароли: {creds_analysis['password_patterns']['strong']} ({(creds_analysis['password_patterns']['strong']/max(1, creds_analysis['total_credentials'])*100):.1f}%)

💀 ПОЛНЫЙ СПИСОК УКРАДЕННЫХ УЧЁТНЫХ ДАННЫХ:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
            
            # Добавляем все украденные креды
            for i, record in enumerate(self.creds_data, 1):
                email = record.get('submitted_email', 'N/A')
                password = record.get('submitted_password', 'N/A')
                ip = record.get('ip_address', 'N/A')
                timestamp = record.get('timestamp', 'N/A')
                
                # Форматируем время
                try:
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    formatted_time = dt.strftime('%Y-%m-%d %H:%M:%S')
                except:
                    formatted_time = timestamp
                
                report += f"\n{i:2d}. Email: {email}"
                report += f"\n    Password: {password}"
                report += f"\n    IP: {ip}"
                report += f"\n    Время: {formatted_time}"
                report += f"\n    {'─' * 50}"

        # Добавляем геоанализ
        if geo_analysis and geo_analysis['credentials_locations']:
            report += f"""

🗺️  ГЕОГРАФИЯ ПОЛУЧЕННЫХ ДАННЫХ:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• Страны (топ-5):"""
            for country, count in list(geo_analysis['country_distribution'].items())[:5]:
                report += f"\n  - {country}: {count} IP адресов"
                
            if geo_analysis['credentials_locations']:
                report += f"""

🔥 КРИТИЧНО! Учётные данные получены из следующих локаций:"""
                for cred_location in geo_analysis['credentials_locations'][:5]:
                    location = cred_location['location']
                    report += f"\n• {cred_location['email']} - {location['city']}, {location['country']} (IP: {cred_location['ip']})"

        report += f"""

🚨 ПОТЕНЦИАЛЬНЫЕ УГРОЗЫ И АНОМАЛИИ:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• Автоматизированные запросы обнаружены: {len(ua_analysis['suspicious_user_agents'])} типов
• Множественные клики с одного IP: {len([ip for ip, count in ip_analysis['repeat_clickers'].items() if count > 10])} адресов
• Подозрительные User-Agent: {len(set(ua_analysis['suspicious_user_agents']))}

📋 ВЫВОДЫ И РЕКОМЕНДАЦИИ:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

        # Аналитические выводы
        if time_analysis['total_clicks'] > 200:
            report += "⚠️  КРИТИЧНО: Очень высокая активность может указывать на автоматизированное сканирование\n"
        
        if len(ip_analysis['suspicious_ips']) > 50:
            report += "⚠️  ВНИМАНИЕ: Обнаружены множественные запросы из облачных провайдеров\n"
            
        if len([count for count in ip_analysis['repeat_clickers'].values() if count > 20]) > 5:
            report += "🔥 КРИТИЧНО: Обнаружены IP с аномально высокой активностью (>20 кликов)\n"
            
        if len(ua_analysis['suspicious_user_agents']) > 0:
            report += "🤖 АВТОМАТИЗАЦИЯ: Обнаружены боты и автоматизированные сканеры\n"
        
        if creds_analysis['total_credentials'] > 0:
            report += f"💀 КРИТИЧНО: Получено {creds_analysis['total_credentials']} учётных записей!\n"
            
        if creds_analysis['password_patterns']['weak'] > creds_analysis['total_credentials'] * 0.5:
            report += "⚠️  ВНИМАНИЕ: Более 50% полученных паролей являются слабыми\n"

        recommendations = [
            "1. Внедрить rate limiting на веб-сервисах",
            "2. Заблокировать подозрительные IP диапазоны: 209.222.82.0/24",
            "3. Усилить мониторинг автоматизированных запросов",
            "4. Провести дополнительное обучение сотрудников по фишингу",
            "5. Рассмотреть внедрение CAPTCHA для подозрительного трафика"
        ]
        
        if creds_analysis['total_credentials'] > 0:
            recommendations.extend([
                "6. 🔥 СРОЧНО: Уведомить затронутых пользователей о компромитации",
                "7. 🔥 СРОЧНО: Принудительно сменить пароли для скомпрометированных аккаунтов",
                "8. Проанализировать доступы скомпрометированных аккаунтов",
                "9. Усилить мониторинг подозрительной активности"
            ])
        
        report += f"""
💡 РЕКОМЕНДАЦИИ ПО БЕЗОПАСНОСТИ:
" + "\n".join(recommendations) + f"

══════════════════════════════════════════════════════════════════
Отчёт сгенерирован: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Анализировал: AKUMA's Phishing Analyzer v1.0
"Доверяй, но проверяй... особенно фишинговые письма!" 😈
══════════════════════════════════════════════════════════════════
"""
        
        return report
    
    def save_detailed_data(self):
        """Сохранение детальных данных для дополнительного анализа"""
        detailed_data = {
            'summary': {
                'total_clicks': len(self.click_data),
                'total_credentials': len(self.creds_data),
                'unique_ips': len(self.unique_ips),
                'analysis_date': datetime.now().isoformat()
            },
            'time_analysis': self.analyze_time_patterns(),
            'ip_analysis': self.analyze_ip_addresses(),
            'user_agent_analysis': self.analyze_user_agents(),
            'credentials_analysis': self.analyze_credentials(),
            'geolocation_analysis': self.analyze_geolocation() if len(self.creds_data) > 0 else None,
            'raw_click_data_sample': self.click_data[:5],
            'raw_creds_data_sample': [{
                'ip': record.get('ip_address', ''),
                'email': record.get('submitted_email', ''),
                'timestamp': record.get('timestamp', ''),
                'user_agent': record.get('user_agent', '')[:100] + '...' if len(record.get('user_agent', '')) > 100 else record.get('user_agent', '')
            } for record in self.creds_data[:10]]  # Показываем креды без паролей для безопасности
        }
        
        output_file = '/home/akuma/Desktop/phishing_analysis_detailed.json'
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(detailed_data, f, ensure_ascii=False, indent=2)
        
        print(f"💾 Детальные данные сохранены в: {output_file}")
        return output_file

def main():
    print("🎯 AKUMA's Phishing Log Analyzer v1.0")
    print("═══════════════════════════════════════")
    
    csv_file = "/home/akuma/Desktop/projects/atacking_google.com-2 - Events.csv"
    analyzer = PhishingLogAnalyzer(csv_file)
    
    # Парсим данные
    if not analyzer.parse_csv():
        print("💥 Ошибка парсинга данных!")
        return
    
    # Генерируем отчёт
    report = analyzer.generate_report()
    
    # Сохраняем отчёт
    report_file = '/home/akuma/Desktop/phishing_report.txt'
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(report)
    
    # Сохраняем детальные данные
    analyzer.save_detailed_data()
    
    print(f"📋 Отчёт сохранён в: {report_file}")
    print("\n" + "═" * 60)
    print("ПРЕВЬЮ ОТЧЁТА:")
    print("═" * 60)
    print(report)

if __name__ == "__main__":
    main()
