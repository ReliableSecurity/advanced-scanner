#!/bin/bash
clear
tput civis  # скрыть курсор

glitch_lines=(
"Ξ Запуск кибердек ядра... [ну наконец-то]"
"Ξ Внедрение системных эксплойтов... [не спрашивай откуда они]"
"Ξ Рукопожатие с нейросетью... [надеемся, что она дружелюбная]"
"Ξ Подмена MAC-адреса... ok [теперь я - принтер HP]"
"Ξ Ректификация сплайнов... ok [никто не знает, что это]"
"Ξ Инициализация модуля анализа целей... [прицел калиброван]"
"Ξ Выпуск дронов SIGINT... [вышли через Wi-Fi соседа]"
"Ξ Подключение к интерфейсу кибервойны... [настраиваю лазерную указку]"
"Ξ ████████████▓▓▓░░░░░░░░░░░░░░░░░░░░░░░░ [10%] загрузка кофеина"
"Ξ ███████████████▓▓▓▓▓▓▓░░░░░░░░░░░░░░░░ [42%] теряется связь с реальностью"
"Ξ ███████████████████████▓▓▓▓▓▓░░░░░░░░ [76%] синхронизация с darknet"
"Ξ ████████████████████████████████████ [100%] ты больше не человек"
)

for line in "${glitch_lines[@]}"; do
  if command -v lolcat &>/dev/null; then
    echo -ne "\e[1;32m$line\e[0m\n" | lolcat
  else
    echo -ne "\e[1;32m$line\e[0m\n"
  fi
  sleep 0.25
done

echo ""
echo -ne "\e[1;35m┌──────────────────────────────────────────────────────┐\e[0m\n"
echo -ne "\e[1;35m│ \e[0m\e[1;36m   HACK MODULE LOADED :: WELCOME, OPERATIVE.   \e[0m\e[1;35m      │\e[0m\n"
echo -ne "\e[1;35m└──────────────────────────────────────────────────────┘\e[0m\n"
sleep 1

for i in {1..30}; do
    echo -ne "\e[32m$(head /dev/urandom | tr -dc 'A-Za-z0-9!@#$%^&*_?' | head -c $((RANDOM % 28 + 12)))\r\e[0m"
    sleep 0.05
done

sleep 0.3

nickname="AKUMA"
for ((i=0; i<${#nickname}; i++)); do
    echo -ne "\e[1;31m${nickname:$i:1}\e[0m"
    sleep 0.2
done

echo -e "\n"
echo -e "\n💀 Все системы онлайн. Если что — это не мы."
echo -e "🧠 Добро пожаловать в матрицу, \e[1;32m$nickname\e[0m... У нас тут sudo и печеньки 🍪."
tput cnorm  # вернуть курсор
echo -e "\n"
# Конфигурация
WORK_DIR="/root/AD"
OUTPUT_DIR="$WORK_DIR/results_$(date +%Y%m%d_%H%M%S)"
LOG_FILE="$OUTPUT_DIR/scan.log"
MAX_PARALLEL=15
TIMEOUT_PER_HOST=300

# Все ваши подсети
SUBNETS=(
    192.168.12.0/22 10.0.82.0/29 192.168.64.0/24 192.168.16.0/24 192.168.77.0/24 
    192.168.2.0/24 10.0.3.0/24 10.0.65.0/24 10.0.50.0/24 10.177.80.32/29 
    172.16.17.0/27 10.0.47.0/24 10.0.48.0/24 192.168.78.0/24 192.168.112.0/22 
    10.0.32.0/24 192.168.180.0/24 10.177.0.0/24 10.0.13.0/24 10.0.44.0/24 
    10.0.4.0/24 10.0.34.0/24 10.0.40.1/32 192.168.65.0/24 10.0.78.0/24 
    10.0.26.0/24 10.0.63.0/24 192.168.119.0/24 10.0.61.0/24 10.40.50.0/24 
    192.168.100.0/24 192.168.74.0/24 10.0.95.0/24 192.168.11.0/24 10.0.40.0/24 
    10.0.76.0/24 192.168.118.0/24 10.177.80.40/29 10.0.12.0/24 10.0.41.1/32 
    192.168.66.0/24 10.0.64.0/20 192.168.79.0/24 10.0.79.0/24 10.0.101.0/24 
    10.177.80.0/28 192.168.23.0/24 172.16.16.0/28 10.0.1.0/24 10.0.82.24/29 
    192.168.120.0/24 192.168.67.0/24 192.168.116.0/24 192.168.0.0/24 192.168.101.0/24 
    10.0.81.0/24 192.168.75.0/24 172.16.1.0/24 10.0.62.0/24 10.0.41.0/24 
    10.0.80.0/24 10.0.94.0/24 172.16.16.32/28 192.168.76.0/24
)

# Полный список всех модулей NetExec
ALL_MODULES=(
    adcs add-computer bitlocker coerce_plus daclread dfscoerce drop-sc 
    empire_exec enum_av enum_ca enum_dns enum_trusts find-computer firefox 
    get-desc-users get-network get-unixUserPassword get-userPassword 
    get_netconnections gpp_autologin gpp_password group-mem groupmembership 
    handlekatz hash_spider hyperv-host iis impersonate install_elevated 
    ioxidresolver keepass_discover keepass_trigger laps ldap-checker lsassy 
    maq masky met_inject mobaxterm mremoteng ms17-010 msol mssql_priv 
    nanodump nopac ntdsutil ntlmv1 obsolete petitpotam pi powershell_history 
    pre2k printerbug printnightmare procdump pso putty rdcman rdp reg-query 
    reg-winlogon runasppl sccm schtask_as scuffy security-questions 
    shadowcoerce slinky smbghost spider_plus spooler subnets teams_localdb 
    test_connection uac user-desc veeam vnc wcc wdigest web_delivery webdav 
    whoami wifi winscp zerologon
)

# Группировка модулей по типам проверок
SMB_MODULES=(
    ms17-010 smbghost zerologon nopac
    petitpotam printnightmare spooler
    coerce_plus netlogon shadowcoerce
    dfscoerce printerbug
)

LDAP_MODULES=(
    ldap-checker enum_trusts find-computer
    subnets obsolete pre2k adcs delegations
    laps gpp_password get-desc-users
    user-desc groupmembership
)

AUX_MODULES=(
    enum_dns enum_ca rdp web_delivery
    vnc mssql_priv wdigest
)

# Создание директорий
mkdir -p "$OUTPUT_DIR/logs" "$OUTPUT_DIR/results" || { 
    echo "Ошибка создания директорий" | tee -a "$LOG_FILE"
    exit 1
}

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Улучшенное сканирование хостов
scan_hosts() {
    local protocol=$1
    local ports=$2
    local out_file="$OUTPUT_DIR/${protocol}_hosts.txt"
    
    log "Сканирование ${protocol} хостов (порты ${ports})..."
    
    nmap -Pn -p${ports} --open --min-rate 100 --max-retries 2 \
         --max-rtt-timeout 1500ms --min-hostgroup 100 \
         "${SUBNETS[@]}" -oG - | awk '/Up$/{print $2}' > "$out_file"
    
    local count=$(wc -l < "$out_file")
    log "Найдено ${count} ${protocol} хостов"
}

# Запуск проверки с обработкой результатов
run_check() {
    local host=$1
    local protocol=$2
    local module=$3
    
    local log_file="$OUTPUT_DIR/logs/${protocol}_${module}_${host//\//_}.log"
    local result_file="$OUTPUT_DIR/results/${protocol}_${module}.txt"
    
    # Запуск проверки
    timeout $TIMEOUT_PER_HOST nxc "$protocol" "$host" -M "$module" > "$log_file" 2>&1
    
    # Обработка результатов для разных модулей
    case $module in
        zerologon|nopac|petitpotam|printnightmare|ms17-010|smbghost)
            grep -q 'VULNERABLE\|Potentially vulnerable\|Vulnerable' "$log_file" && {
                echo "$host - $(grep -m1 'VULNERABLE\|Potentially vulnerable\|Vulnerable' "$log_file")" >> "$result_file"
            }
            ;;
        *)
            grep -q '[+]' "$log_file" && {
                echo "$host - $(grep -m1 '[+]' "$log_file")" >> "$result_file"
            }
            ;;
    esac
    
    # Удаляем пустые логи (размером меньше 50 байт)
    [ $(stat -c%s "$log_file" 2>/dev/null || echo 0) -lt 50 ] && rm -f "$log_file"
}

# Основной цикл проверок
main_checks() {
    # 1. Обнаружение хостов
    scan_hosts "smb" "445"
    scan_hosts "ldap" "389,636"
    scan_hosts "rdp" "3389"
    scan_hosts "mssql" "1433"
    
    # 2. SMB проверки
    for module in "${SMB_MODULES[@]}"; do
        log "Запуск SMB проверки: $module"
        count=0
        while IFS= read -r host; do
            run_check "$host" "smb" "$module" &
            (( ++count % MAX_PARALLEL == 0 )) && wait
        done < "$OUTPUT_DIR/smb_hosts.txt"
        wait
        
        # Создаем файл, даже если результатов нет
        touch "$OUTPUT_DIR/results/smb_${module}.txt"
    done
    
    # 3. LDAP проверки
    for module in "${LDAP_MODULES[@]}"; do
        log "Запуск LDAP проверки: $module"
        count=0
        while IFS= read -r host; do
            run_check "$host" "ldap" "$module" &
            (( ++count % MAX_PARALLEL == 0 )) && wait
        done < "$OUTPUT_DIR/ldap_hosts.txt"
        wait
        touch "$OUTPUT_DIR/results/ldap_${module}.txt"
    done
    
    # 4. Дополнительные проверки
    for module in "${AUX_MODULES[@]}"; do
        case $module in
            enum_dns|enum_ca)
                log "Запуск DNS/CA проверок"
                nxc dns "${SUBNETS[@]}" -M "$module" > "$OUTPUT_DIR/logs/${module}.log" 2>&1
                grep '[+]' "$OUTPUT_DIR/logs/${module}.log" > "$OUTPUT_DIR/results/${module}.txt" || true
                ;;
            rdp|vnc|mssql_priv)
                proto="${module%_*}"
                log "Проверка $proto ($module)"
                count=0
                while IFS= read -r host; do
                    run_check "$host" "$proto" "$module" &
                    (( ++count % MAX_PARALLEL == 0 )) && wait
                done < "$OUTPUT_DIR/${proto}_hosts.txt"
                wait
                touch "$OUTPUT_DIR/results/${proto}_${module}.txt"
                ;;
            *)
                log "Пропуск неподдерживаемого модуля: $module"
                ;;
        esac
    done
}

# Генерация итогового отчета
generate_report() {
    local report="$OUTPUT_DIR/FINAL_REPORT.txt"
    
    echo "=== ИТОГОВЫЙ ОТЧЕТ ===" > "$report"
    echo "Дата: $(date)" >> "$report"
    echo "Проверенные подсети:" >> "$report"
    printf "  %s\n" "${SUBNETS[@]}" >> "$report"
    
    echo -e "\n=== КРИТИЧЕСКИЕ УЯЗВИМОСТИ ===" >> "$report"
    grep -r -h 'VULNERABLE\|CRITICAL' "$OUTPUT_DIR/results" >> "$report"
    
    echo -e "\n=== ПОТЕНЦИАЛЬНЫЕ УЯЗВИМОСТИ ===" >> "$report"
    grep -r -h 'Potentially vulnerable\|WARNING' "$OUTPUT_DIR/results" >> "$report"
    
    echo -e "\n=== КОНФИДЕНЦИАЛЬНЫЕ ДАННЫЕ ===" >> "$report"
    grep -r -h 'Password\|Hash\|Secret\|Credential' "$OUTPUT_DIR/results" >> "$report"
    
    echo -e "\n=== ВСЕ АКТИВНЫЕ ХОСТЫ ===" >> "$report"
    echo "SMB (445/tcp): $(wc -l < "$OUTPUT_DIR/smb_hosts.txt")" >> "$report"
    echo "LDAP (389,636/tcp): $(wc -l < <(cat "$OUTPUT_DIR/ldap_hosts.txt" 2>/dev/null || echo ""))" >> "$report"
    echo "RDP (3389/tcp): $(wc -l < "$OUTPUT_DIR/rdp_hosts.txt")" >> "$report"
    echo "MSSQL (1433/tcp): $(wc -l < "$OUTPUT_DIR/mssql_hosts.txt")" >> "$report"
    
    # Добавляем список всех проверенных модулей
    echo -e "\n=== ПРОВЕРЕННЫЕ МОДУЛИ ===" >> "$report"
    printf "SMB: %s\n" "${SMB_MODULES[@]}" >> "$report"
    printf "LDAP: %s\n" "${LDAP_MODULES[@]}" >> "$report"
    printf "Другие: %s\n" "${AUX_MODULES[@]}" >> "$report"
}

# Очистка пустых файлов
cleanup() {
    log "Очистка пустых файлов..."
    find "$OUTPUT_DIR/logs" -type f -size 0 -delete
    find "$OUTPUT_DIR/results" -type f -size 0 -delete
}

main() {
    log "Начало сканирования"
    log "Проверяемые подсети:"
    printf "  %s\n" "${SUBNETS[@]}" | tee -a "$LOG_FILE"
    
    main_checks
    cleanup
    generate_report
    
    log "Проверка завершена. Отчет: $OUTPUT_DIR/FINAL_REPORT.txt"
    
    # Вывод краткой статистики
    echo -e "\n\e[1;36m=== КРАТКАЯ СТАТИСТИКА ===\e[0m"
    echo -e "Найдено уязвимых систем:"
    grep -r -h 'VULNERABLE\|CRITICAL' "$OUTPUT_DIR/results" | wc -l | awk '{print "  Критические: " $1}'
    grep -r -h 'Potentially vulnerable\|WARNING' "$OUTPUT_DIR/results" | wc -l | awk '{print "  Предупреждения: " $1}'
    echo -e "\nПолный отчет: \e[1;33m$OUTPUT_DIR/FINAL_REPORT.txt\e[0m"
}

main
