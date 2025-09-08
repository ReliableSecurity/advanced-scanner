#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AKUMA Burp Cookie Extractor
Извлекает cookie из Burp Suite запроса для использования с тестером
"""

import re
import urllib.parse
from colorama import Fore, Style, init

init(autoreset=True)

def extract_cookie_from_burp_request():
    """Извлекает cookie строку из вставленного Burp запроса"""
    
    print(f"{Fore.CYAN}🍪 AKUMA Cookie Extractor{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Вставь сюда твой Burp Suite запрос (нажми Enter дважды для завершения):{Style.RESET_ALL}")
    
    lines = []
    empty_count = 0
    
    while empty_count < 2:
        line = input()
        if line.strip() == "":
            empty_count += 1
        else:
            empty_count = 0
        lines.append(line)
    
    burp_request = "\n".join(lines)
    
    # Ищем строку Cookie
    cookie_match = re.search(r'^Cookie:\s*(.+)$', burp_request, re.MULTILINE)
    
    if cookie_match:
        cookie_string = cookie_match.group(1).strip()
        
        print(f"\n{Fore.GREEN}✅ Cookie найдены!{Style.RESET_ALL}")
        print(f"\n{Fore.CYAN}Полная cookie строка:{Style.RESET_ALL}")
        print(f"'{cookie_string}'")
        
        print(f"\n{Fore.CYAN}Команда для запуска тестера:{Style.RESET_ALL}")
        print(f"./akuma_xss_tester.py -u https://www.perekrestok.ru -c '{cookie_string}' --authenticated")
        
        print(f"\n{Fore.CYAN}Или только аутентифицированные тесты:{Style.RESET_ALL}")
        print(f"./akuma_xss_tester.py -u https://www.perekrestok.ru -c '{cookie_string}' --authenticated")
        
        # Парсим отдельные cookie
        print(f"\n{Fore.YELLOW}Найденные cookie:{Style.RESET_ALL}")
        cookies = cookie_string.split(';')
        for i, cookie in enumerate(cookies, 1):
            cookie = cookie.strip()
            if '=' in cookie:
                key, value = cookie.split('=', 1)
                print(f"  {i:2d}. {Fore.CYAN}{key}{Style.RESET_ALL} = {value[:50]}{'...' if len(value) > 50 else ''}")
        
        return cookie_string
        
    else:
        print(f"\n{Fore.RED}❌ Cookie не найдены в запросе!{Style.RESET_ALL}")
        print("Убедись, что в запросе есть строка 'Cookie: ...'")
        return None

if __name__ == "__main__":
    # Пример с твоими cookie
    sample_cookie = """spid=1756112841958_4c096f20c66abdac28ec54aaffa842d5_76mlkl21lv3kc09l; spsc=1756216600958_83313597af4ecd431b23b83c410c42c5_FPDExzM101Zqz5A.XWtShc0SmnrJP1kBcS3xvkUr77RC0h8jn4A4WCvbEtxTSlABZ; session=j:{"accessToken":"eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJFRlBVcWRLamZTVG9vR085OWRpLURKQk4zWkgyaUxlcE5yWTF3dXgyNHFvIn0.eyJleHAiOjE3NTYyMTY5NjEsImlhdCI6MTc1NjIxNjYwMSwiYXV0aF90aW1lIjoxNzU2MTA5NDAxLCJqdGkiOiIxYjE0YjM4MC00YTFlLTRhMWEtYjU1Yi1iNDAzNTQzZDM2N2QiLCJpc3MiOiJodHRwczovL2lkLng1LnJ1L2F1dGgvcmVhbG1zL3Nzb3g1aWQiLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiZjo2NmI5YWQ2MC00Y2I0LTRlZTEtYjlhMC0wNTI4ZmRlYWMyYjE6MTAyNzM0OTAxIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoidGN4X3dlYiIsInNlc3Npb25fc3RhdGUiOiJkNmQ5OWJiMi0wMzQzLTQ5ZjItOWExMi01NmMzN2RlNDJkMDciLCJhY3IiOiIxIiwiYWxsb3dlZC1vcmlnaW5zIjpbIioiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50Iiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJvcGVuaWQgb2ZmbGluZV9hY2Nlc3MgcHJvZmlsZSBlbWFpbCIsInNpZCI6ImQ2ZDk5YmIyLTAzNDMtNDlmMi05YTEyLTU2YzM3ZGU0MmQwNyIsInNvdXJjZV9kZXRhaWwiOiJ3ZWIiLCJwZXJtaXNzaW9uTWFya2V0aW5nIjoiTiIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwicHJlZmVycmVkX3VzZXJuYW1lIjoiNzkxMDYwMTUzODEiLCJjaXBfaWQiOiJJRFguMTAyNzM0OTAxIiwieDVpZCI6IjEwMjczNDkwMSJ9.Fp_6FV8zX1r5o_7tH8kbr_dr7Wm7lLof3Uyo5dfP3tix0zojEZ9N_pObcmr_xzrAHnGeaBncRdoQ-JQ0cKw4CjLHBiR-F9jELya4UDdJ7FXRT_aXi_eu7CnBOMhlbGGQRkMELdq8LZFPqKjPIqqdeA781FxUQvUR9t8pjRJVtjpSZ2WlMKuzc88Cnw2-AFOeVoKE8FEWKiw7z73rfFo8KI2G1yEEDirRShFhhK7OTyL7ZIpEAdCXUTRZJqZ9w-Sx_Du19tGD0AZur6ZfztitG6N0DGjApfDgiLPr-GZg4Ih-DJ80bcs6M5wzI_IxQurcGKm1wlzskjbAR96Yfk9mFw","refreshToken":"eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI2MmE2YTcwYS0wOGNkLTQwMTktOGFiYy0zYjg4ZjVkODYzNzAifQ.eyJpYXQiOjE3NTYyMTY2MDEsImp0aSI6ImQzNWJjNmRkLTQ3M2UtNDc2NC05MTY0LTYwMTcxNTJiNzUxYSIsImlzcyI6Imh0dHBzOi8vaWQueDUucnUvYXV0aC9yZWFsbXMvc3NveDVpZCIsImF1ZCI6Imh0dHBzOi8vaWQueDUucnUvYXV0aC9yZWFsbXMvc3NveDVpZCIsInN1YiI6ImY6NjZiOWFkNjAtNGNiNC00ZWUxLWI5YTAtMDUyOGZkZWFjMmIxOjEwMjczNDkwMSIsInR5cCI6Ik9mZmxpbmUiLCJhenAiOiJ0Y3hfd2ViIiwic2Vzc2lvbl9zdGF0ZSI6ImQ2ZDk5YmIyLTAzNDMtNDlmMi05YTEyLTU2YzM3ZGU0MmQwNyIsInNjb3BlIjoib3BlbmlkIG9mZmxpbmVfYWNjZXNzIHByb2ZpbGUgZW1haWwiLCJzaWQiOiJkNmQ5OWJiMi0wMzQzLTQ5ZjItOWExMi01NmMzN2RlNDJkMDcifQ.twtz3i1LB4xiXDX1U9TwSsn-GeL5w8engzSVRenZg68","accessTokenExpiredAt":1756216961000,"refreshTokenExpiredAt":2071749401214,"device":{"uuid":"363e22da-3cc1-477c-93a4-81eefb3c8ef1"}}; agreements=j:{"isAdultContentEnabled":true,"isAppAppInstallPromptClosed":true}; _ym_uid=1756108143333243072; _ym_d=1756108143; _ymab_param=VhncJcBfPgLFgZlAx3lDVbrEkF7H6IUaQDubGzcJAViz7HBav4pxWFHMRv6A8oXeaJUNAzSGHAJVkld1r5EF6nUxiAs; isSubscriptionHidden=true; spjs=1756112909831_3e2fefe3_013500c3_47bea5019ace7b541b6c5a2e6d0e2d3a_64l1ddkBnO2wiVQid82Sq24sMrL2Tzvq7oNHM5Kq3j4fAIyJFXh1ZTkETXuSStMjWjOv6hZeJYI8v3mJvk+CQzasWTtyeu8fS3On2AQzjc01HMCFfBFu3rIaVkebQ68PM1TlwHRcbLndhQRilo6af24kkCB1TBRFuJDJeKGZ1eApV547Ml8nl9vzD23slIAQUSj5zCglF/Ixr18bj8fDQyJdscRocD394exlFq+HjksXa8fyXnNIiImk1/L2zN5/PhR6IWXH6JkYYIbYVV1RoSnxjE1wSJBmqpLvKabvwoN/XGmvudH1tTSJ2aqYNvIihwv/y99XXM1QicUijJSo2MD69qZqQh//s5pQRWDpzQ3IhCGxNWz6652kUyJUz7is+pU4+PFMlWXfcT1uUOk1M2/iCflBaEW1VVoOG97gxIY2CPnp/VQQtRSs2AH7xT4cIBnFtWlRTr7i2kZ3q5PPP2NUgPAkHA3quSZaAeXEuXl9hNGgfewHtzlSfz7w7lbGChHdrH0JNsX4kHwL74fTcyYfyqpeRlHBpa1ZKP5l8GA0C9eXe3Mu3oK6ZiX58Y19MQjklHthW2vehwKilM7Iyp0mwoIGfiurv7cijbNAp0a7AP6eYloXRXkBXCzxSJZkOo/Yq3xHEUL2Dlsp+cWV4TYpCAq8zzlus4rXJPrAHm0yClWheUWXyjWIUYPxz53gGYHW5fs4YemtjdEw/cyEqC0Pf+1Su7Yy7dV42vebYbPONupbAWhFtVVaDhtesHU04Fr/P0/J3w9Lc6fYBDxvfJd6d1byQuzmMQjdJArNfB6RERW1kQgs3KmAAPby6w+/KiNBgRTEFxazAy7+8sWSJGoB24kzwRQXtWAti29GEmK23tqifbQdkZGkiTnc9rBzJa2nJ1piOgvWHhKx68WrmhYOI4JvBo0dXiV3x5Ja3v4sAaf1E7o+3u6AJWpxyATkOcDYWVBNI3NvF5s70uqwgVybnz9tQ2S20Hl8H6/B5CS3D0srfoYZGJGMYbAsVFh5EKmhc47niip2mnYgkfn9TRlVQcFwfU/avvZyI/fayx5aQKzMYHhV1SnEbT99CbbFuRDMvGBYA/OjK5uor+awYieteSF1TRjiNYPgNdnjVr8a2v92U5I0PZhZd6db4PzsIQfCI2NFus+xdkeBVU2YaTyE0qB2zBHHG1l6hDb7xmY4Bcsm7o2B6vUNNrUM0kNnMKqcqn; TS015bfe9d=0147334a4aec204e71ac82edd54fd0d5a6bdbbd920dcf50aa2b3ce81e93fe4e03c4d04a9675a6950d2fe93391d8bbd69323dad1c597a9e555a21327550f32a56962d858710"""
    
    print(f"{Fore.GREEN}🔥 Готовая команда для твоих cookie:{Style.RESET_ALL}")
    print(f"\n./akuma_xss_tester.py -u https://www.perekrestok.ru -c '{sample_cookie}' --authenticated")
    
    print(f"\n{Fore.YELLOW}Если хочешь извлечь cookie из другого Burp запроса, запусти без параметров:{Style.RESET_ALL}")
    print("python3 burp_to_cookie.py")
    
    extract_cookie_from_burp_request()
