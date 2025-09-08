# 🔥 AKUMA's Ultimate SMTP Vulnerability Scanner 

Легендарный набор инструментов для массового сканирования SMTP relay уязвимостей!

## 🎯 Файлы проекта

### 1. `mass_smtp_hunter.py` - Базовый массовый сканер
- Быстрое сканирование всех целей
- Поддержка многопоточности
- Результаты в JSON формате

### 2. `ultimate_smtp_scanner.py` - Продвинутый сканер (ОСНОВНОЙ)
- Расширенный список портов: 25, 587, 465, 2525, 1025, 26, 2526
- Детектирование AUTH и TLS поддержки
- Анализ SMTP банеров
- Статистика безопасности
- Красивые отчёты

### 3. `smtp_evasion_toolkit.py` - Модуль продвинутых техник
- Domain spoofing
- Header injection
- Address obfuscation  
- Auth bypass попытки
- HELO variations

### 4. `quick_test.py` - Быстрый тест одного сервера

## 🚀 Использование

### Базовое сканирование (рекомендуется)
```bash
python3 ultimate_smtp_scanner.py
```

### Быстрое сканирование (больше потоков)
```bash
python3 ultimate_smtp_scanner.py -t 20 --timeout 10
```

### Глубокое сканирование (с evasion техниками)
```bash
python3 ultimate_smtp_scanner.py --deep -t 5
```

### Тест одного сервера
```bash
python3 quick_test.py
```

## 🎯 Целевые домены (24 компании)

```
medel.com               104.16.4.14
nurotron.com           101.37.86.137
advancedbionics.com    194.116.180.178
cochlear.com           103.149.202.33
swissvalley.com        104.219.41.214
strongco.com           62.28.179.91
rib-software.com       3.64.244.87
psas.cz                93.185.102.225
powerfleet.com         92.112.186.38
pollardbanknote.com    162.159.135.42
panerabread.com        204.52.196.176
nwn.ai                 141.193.213.10
newwedsfoods.com       (auto-resolve)
msrcosmos.com          20.49.104.41
jas.com                75.2.70.75
everi.com              141.193.213.21
episource.com          141.193.213.10
csc-usa.com            151.101.1.195
catapultsports.com     141.193.213.10
cadence.com            35.167.1.114
brenntag.com           172.67.137.170
atlanticahotels.com    20.8.80.89
bankerlopez.com        141.193.213.11
becht.com              198.12.235.42
```

## 📊 Что ищем

### 🚨 CRITICAL - Открытые SMTP relay
- Принимают MAIL FROM с внешних доменов
- Разрешают RCPT TO на внешние домены  
- Можно использовать для фишинга

### 🎭 ADVANCED - Evasion техники
- Domain spoofing (поддомены цели)
- Header injection попытки
- Address obfuscation
- Auth bypass (слабые пароли)

### 🛡️ INFO - Конфигурация безопасности
- Поддержка AUTH
- Поддержка TLS/STARTTLS
- Версии SMTP сервера
- Банеры сервера

## 💡 AKUMA's Pro Tips

1. **Время сканирования**: С дефолтными настройками ~20-30 минут
2. **Уважай rate limits**: Не используй >20 потоков
3. **Timeout**: Если много таймаутов - уменьши до 10 сек
4. **Результаты**: Все результаты сохраняются в JSON файлы
5. **Legal disclaimer**: Только на своих/авторизованных системах!

## 🏆 Workflow для Bug Bounty

1. Запусти базовое сканирование:
   ```bash
   python3 ultimate_smtp_scanner.py -t 15 --timeout 12
   ```

2. Если найдены уязвимости - запусти deep scan:
   ```bash
   python3 ultimate_smtp_scanner.py --deep -t 5
   ```

3. Создай тикеты для уязвимых серверов

4. Profit! 💰

## 🔥 Легендарные фичи

- **Real-time прогресс** с красивыми иконками
- **Умная статистика** по безопасности
- **JSON отчёты** для дальнейшего анализа
- **Многопоточность** для скорости
- **Graceful error handling** 
- **Expandable architecture**

---

*"Hack the planet, one SMTP server at a time!" - AKUMA*

🎯 Remember: Scan responsibly, exploit ethically!
