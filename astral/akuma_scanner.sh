#!/bin/bash

# ========================================================================
# AKUMA'S ADVANCED LOW-HANGING FRUIT SCANNER v2.0
# "Если твоя инфраструктура не плачет после этого скрипта - ты делаешь что-то не так"
# ========================================================================

set -euo pipefail

# Глобальные переменные и конфигурация
declare -g SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
declare -g CONFIG_FILE="${SCRIPT_DIR}/scanner_config.conf"
declare -g WORK_DIR="${HOME}/lowhanging_results"
declare -g OUTPUT_DIR="${WORK_DIR}/scan_$(date +%Y%m%d_%H%M%S)"
declare -g LOG_FILE="${OUTPUT_DIR}/scanner.log"
declare -g VULNERABILITY_DB="${OUTPUT_DIR}/vulnerabilities.db"

# Конфигурационные параметры
declare -g MAX_PARALLEL=20
declare -g TIMEOUT_PER_HOST=300
declare -g NMAP_THREADS=100
declare -g DEBUG_MODE=false
declare -g AUTHENTICATED_SCAN=false
declare -g USERNAME=""
declare -g PASSWORD=""
declare -g DOMAIN=""

# Цветовая схема для вывода
declare -gr RED='\033[0;31m'
declare -gr GREEN='\033[0;32m'
declare -gr YELLOW='\033[1;33m'
declare -gr BLUE='\033[0;34m'
declare -gr PURPLE='\033[0;35m'
declare -gr CYAN='\033[0;36m'
declare -gr WHITE='\033[1;37m'
declare -gr NC='\033[0m' # No Color
declare -gr BOLD='\033[1m'

# Массивы подсетей (по умолчанию пустой - пользователь должен указать)
DEFAULT_SUBNETS=()

# Массивы модулей по критичности
declare -a CRITICAL_MODULES=(
    "zerologon" "ms17-010" "smbghost" "printnightmare" 
    "petitpotam" "nopac" "shadowcoerce"
)

declare -a HIGH_MODULES=(
    "spooler" "coerce_plus" "printerbug" "dfscoerce"
    "webdav" "sccm" "lsassy" "nanodump"
)

declare -a MEDIUM_MODULES=(
    "enum_trusts" "ldap-checker" "gpp_password" "laps"
    "adcs" "pre2k" "maq" "rdp" "vnc"
)

declare -a LOW_MODULES=(
    "enum_dns" "enum_ca" "get-desc-users" "user-desc"
    "subnets" "groupmembership" "find-computer"
)

declare -a AUTHENTICATED_MODULES=(
    "bloodhound" "lsassy" "nanodump" "dpapi" "handlekatz"
    "secrets" "sam" "ntds" "dcsync" "kerberoasting"
    "asreproast" "golden" "silver" "sid-history"
)

# ========================================================================
# УТИЛИТЫ И ХЕЛПЕРЫ
# ========================================================================

show_banner() {
    clear
    echo -e "${RED}"
    cat << "EOF"
    ╔══════════════════════════════════════════════════════════════════════════════╗
    ║                      🔥 AKUMA'S ADVANCED SCANNER 🔥                          ║
    ║                    "Low-hanging fruits never tasted so good"                 ║
    ║                                                                              ║
    ║  [WARNING] Этот скрипт может разорвать твою инфраструктуру как мокрую газету ║
    ╚══════════════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    
    echo -e "${CYAN}[INFO]${NC} Initializing advanced penetration testing framework..."
    echo -e "${YELLOW}[WARNING]${NC} Use only on authorized networks. AKUMA не несёт ответственности за твои безумные идеи!"
    echo ""
    sleep 2
}

log() {
    local level="$1"
    local message="$2"
    local timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    
    case "$level" in
        "INFO")  echo -e "${CYAN}[INFO]${NC}  [${timestamp}] ${message}" | tee -a "$LOG_FILE" ;;
        "WARN")  echo -e "${YELLOW}[WARN]${NC}  [${timestamp}] ${message}" | tee -a "$LOG_FILE" ;;
        "ERROR") echo -e "${RED}[ERROR]${NC} [${timestamp}] ${message}" | tee -a "$LOG_FILE" ;;
        "SUCCESS") echo -e "${GREEN}[SUCCESS]${NC} [${timestamp}] ${message}" | tee -a "$LOG_FILE" ;;
        "DEBUG") 
            if [[ "$DEBUG_MODE" == "true" ]]; then
                echo -e "${PURPLE}[DEBUG]${NC} [${timestamp}] ${message}" | tee -a "$LOG_FILE"
            fi
            ;;
        *) echo -e "[${timestamp}] ${message}" | tee -a "$LOG_FILE" ;;
    esac
}

check_dependencies() {
    log "INFO" "Checking dependencies..."
    
    local required_tools=("nmap" "netexec" "nxc")
    local missing_tools=()
    
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log "ERROR" "Missing required tools: ${missing_tools[*]}"
        echo -e "${RED}[ERROR]${NC} Install missing tools first, you fucking noob!"
        exit 1
    fi
    
    # Проверяем версию NetExec
    if command -v nxc &>/dev/null; then
        local nxc_version=$(nxc --version 2>/dev/null | head -n1 || echo "unknown")
        log "INFO" "NetExec version: $nxc_version"
    fi
    
    log "SUCCESS" "All dependencies are satisfied"
}

create_directories() {
    local dirs=(
        "$OUTPUT_DIR"
        "$OUTPUT_DIR/logs"
        "$OUTPUT_DIR/results"
        "$OUTPUT_DIR/raw_results"
        "$OUTPUT_DIR/reports"
        "$OUTPUT_DIR/evidence"
    )
    
    for dir in "${dirs[@]}"; do
        mkdir -p "$dir" || {
            log "ERROR" "Failed to create directory: $dir"
            exit 1
        }
    done
    
    log "INFO" "Created output directories in: $OUTPUT_DIR"
}

load_configuration() {
    # Сначала тихо загружаем конфиг для получения WORK_DIR
    if [[ -f "$CONFIG_FILE" ]]; then
        # shellcheck source=/dev/null
        source "$CONFIG_FILE"
        
        # Update OUTPUT_DIR if WORK_DIR was changed in config
        if [[ -n "$WORK_DIR" ]] && [[ "$WORK_DIR" != "${HOME}/lowhanging_results" ]]; then
            OUTPUT_DIR="${WORK_DIR}/scan_$(date +%Y%m%d_%H%M%S)"
            LOG_FILE="${OUTPUT_DIR}/scanner.log"
            VULNERABILITY_DB="${OUTPUT_DIR}/vulnerabilities.db"
        fi
        
        echo "[INFO] Loading configuration from: $CONFIG_FILE"
    else
        echo "[WARN] Configuration file not found, using defaults"
        create_default_config
    fi
    
    # Validate that subnets are configured
    if [[ ${#SUBNETS[@]} -eq 0 ]]; then
        log "ERROR" "No subnets configured! Please edit $CONFIG_FILE or use command line options."
        echo -e "${RED}ERROR:${NC} No target subnets specified!"
        echo "Please either:"
        echo "1. Edit the configuration file: $CONFIG_FILE"
        echo "2. Use command line: $0 --subnet 192.168.1.0/24"
        exit 1
    fi
}

create_default_config() {
    cat > "$CONFIG_FILE" << 'EOF'
# AKUMA's Advanced Scanner Configuration
# Modify these settings according to your needs

# Subnets to scan (space-separated) - REPLACE WITH YOUR TARGET NETWORKS!
SUBNETS=(
    # "192.168.1.0/24"    # Example: Internal network
    # "10.0.0.0/16"       # Example: Corporate network
    # "172.16.0.0/12"     # Example: Private network
)

# Parallel execution settings
MAX_PARALLEL=20
TIMEOUT_PER_HOST=300
NMAP_THREADS=100

# Authentication settings (CHANGE THESE!)
AUTHENTICATED_SCAN=false
USERNAME=""
PASSWORD=""
DOMAIN=""

# Debug mode
DEBUG_MODE=false
EOF
    log "INFO" "Created default configuration file: $CONFIG_FILE"
    log "WARN" "Please edit $CONFIG_FILE to configure target subnets!"
}

# ========================================================================
# СКАНИРОВАНИЕ И ОБНАРУЖЕНИЕ
# ========================================================================

perform_port_scan() {
    local protocol="$1"
    local ports="$2"
    local output_file="$OUTPUT_DIR/${protocol}_hosts.txt"
    
    log "INFO" "Scanning for $protocol services on ports: $ports"
    
    # Оптимизированные параметры nmap для быстрого сканирования
    local scan_type="-sT"  # TCP connect scan (не требует root)
    if [[ $EUID -eq 0 ]]; then
        scan_type="-sS"       # SYN scan (быстрее, но нужен root)
    fi
    
    local nmap_opts=(
        -Pn                    # Не пинговать хосты
        "$scan_type"           # Тип сканирования
        -p"$ports"             # Порты для сканирования
        --open                 # Только открытые порты
        --min-rate 1000        # Минимальная скорость
        --max-retries 2        # Максимум попыток
        --max-rtt-timeout 1500ms
        --min-hostgroup 50     # Группировка хостов
        --randomize-hosts      # Рандомизация порядка
        -oG -                  # Grep-формат в stdout
    )
    
    # Получаем подсети из конфигурации
    local subnets=("${SUBNETS[@]}")
    
    # Запускаем nmap и извлекаем IP-адреса с портами в формате IP:port
    local temp_file="$(mktemp)"
    nmap "${nmap_opts[@]}" "${subnets[@]}" 2>/dev/null > "$temp_file"
    
    # Парсим результаты nmap и создаем список IP:port (простое решение)
    > "$output_file"
    
    # Простое решение: парсим awk'ом
    awk '
    /^Host:.*Ports:/ {
        ip = $2;
        # Извлекаем часть с портами
        ports_part = $0;
        gsub(/.*Ports: /, "", ports_part);
        gsub(/[[:space:]]*Ignored.*/, "", ports_part);
        
        # Разбираем порты (разделитель: запятая)
        split(ports_part, port_array, ", ");
        for(i in port_array) {
            if(port_array[i] ~ /\/open\//) {
                split(port_array[i], port_details, "/");
                port = port_details[1];
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", port); # trim
                if(port != "") {
                    print ++counter "|" ip ":" port;
                }
            }
        }
    }
    ' "$temp_file" > "$output_file"
    
    rm -f "$temp_file"
    
    local host_count=$(wc -l < "$output_file")
    log "SUCCESS" "Found $host_count $protocol hosts"
    
    # Сохраняем детальную информацию для отчёта
    if [[ $host_count -gt 0 ]]; then
        echo "# $protocol Hosts Discovery Report" > "$OUTPUT_DIR/raw_results/${protocol}_discovery.txt"
        echo "# Scan performed at: $(date)" >> "$OUTPUT_DIR/raw_results/${protocol}_discovery.txt"
        echo "# Ports scanned: $ports" >> "$OUTPUT_DIR/raw_results/${protocol}_discovery.txt"
        echo "# Total hosts found: $host_count" >> "$OUTPUT_DIR/raw_results/${protocol}_discovery.txt"
        echo "" >> "$OUTPUT_DIR/raw_results/${protocol}_discovery.txt"
        cat "$output_file" >> "$OUTPUT_DIR/raw_results/${protocol}_discovery.txt"
    fi
}

perform_service_discovery() {
    log "INFO" "Starting comprehensive service discovery"
    
    # Основные сервисы для сканирования
    perform_port_scan "smb" "445"
    perform_port_scan "ldap" "389,636,3268,3269"
    perform_port_scan "rdp" "3389"
    perform_port_scan "mssql" "1433,1434"
    perform_port_scan "winrm" "5985,5986"
    perform_port_scan "http" "80,443,8080,8443,9090"
    perform_port_scan "ftp" "21"
    perform_port_scan "ssh" "22"
    perform_port_scan "telnet" "23"
    perform_port_scan "dns" "53"
    
    log "SUCCESS" "Service discovery completed"
}

# ========================================================================
# МОДУЛЬНЫЕ ПРОВЕРКИ УЯЗВИМОСТЕЙ
# ========================================================================

run_vulnerability_check() {
    local host="$1"
    local protocol="$2"
    local module="$3"
    local priority="$4"
    local auth_required="$5"
    
    local log_file="$OUTPUT_DIR/logs/${protocol}_${module}_${host//\//_}.log"
    local result_file="$OUTPUT_DIR/results/${priority}_${protocol}_${module}.txt"
    
    log "DEBUG" "Testing $host with $protocol/$module (Priority: $priority)"
    
    # Строим команду для NetExec
    local nxc_cmd=("nxc" "$protocol" "$host" "-M" "$module")
    
    # Добавляем аутентификацию если требуется
    if [[ "$auth_required" == "true" ]] && [[ "$AUTHENTICATED_SCAN" == "true" ]]; then
        nxc_cmd+=("-u" "$USERNAME" "-p" "$PASSWORD")
        if [[ -n "$DOMAIN" ]]; then
            nxc_cmd+=("-d" "$DOMAIN")
        fi
    fi
    
    # Запускаем проверку с таймаутом
    if timeout "$TIMEOUT_PER_HOST" "${nxc_cmd[@]}" > "$log_file" 2>&1; then
        # Анализируем результаты в зависимости от модуля
        analyze_module_results "$module" "$log_file" "$result_file" "$host" "$priority"
    else
        log "DEBUG" "Timeout or error for $host/$module"
        echo "TIMEOUT/ERROR: $host" >> "${result_file}.errors"
    fi
    
    # Удаляем пустые или бесполезные логи
    if [[ -f "$log_file" ]] && [[ $(stat -c%s "$log_file" 2>/dev/null || echo 0) -lt 100 ]]; then
        rm -f "$log_file"
    fi
}

analyze_module_results() {
    local module="$1"
    local log_file="$2" 
    local result_file="$3"
    local host="$4"
    local priority="$5"
    
    local vulnerability_found=false
    local vulnerability_details=""
    
    case "$module" in
        # Критические уязвимости
        zerologon)
            if grep -qi "vulnerable\|exploitable\|zerologon.*success" "$log_file"; then
                vulnerability_details="ZEROLOGON VULNERABILITY DETECTED - CRITICAL RCE"
                vulnerability_found=true
            fi
            ;;
        ms17-010)
            if grep -qi "vulnerable\|ms17-010.*vulnerable\|eternalblue" "$log_file"; then
                vulnerability_details="MS17-010 (EternalBlue) - CRITICAL RCE"
                vulnerability_found=true
            fi
            ;;
        smbghost)
            if grep -qi "vulnerable\|potentially vulnerable\|smbghost.*vulnerable\|cve-2020-0796" "$log_file"; then
                vulnerability_details="SMBGhost (CVE-2020-0796) - CRITICAL RCE"
                vulnerability_found=true
            fi
            ;;
        printnightmare)
            if grep -qi "vulnerable\|potentially vulnerable\|printnightmare.*vulnerable\|cve-2021-34527" "$log_file"; then
                vulnerability_details="PrintNightmare - CRITICAL RCE/LPE"
                vulnerability_found=true
            fi
            ;;
        petitpotam)
            if grep -qi "vulnerable\|potentially vulnerable\|petitpotam.*vulnerable\|coercible" "$log_file"; then
                vulnerability_details="PetitPotam - NTLM Relay Attack Possible"
                vulnerability_found=true
            fi
            ;;
        
        # Высокоприоритетные уязвимости
        spooler|coerce_plus|printerbug|dfscoerce)
            if grep -qi "vulnerable\|coercible\|attack possible" "$log_file"; then
                vulnerability_details="Authentication Coercion Attack Possible - ${module^^}"
                vulnerability_found=true
            fi
            ;;
        
        # Информационные модули
        laps)
            if grep -qi "laps\|password\|readable" "$log_file"; then
                vulnerability_details="LAPS passwords may be readable"
                vulnerability_found=true
            fi
            ;;
        gpp_password)
            if grep -qi "password\|cpassword" "$log_file"; then
                vulnerability_details="GPP passwords found in SYSVOL"
                vulnerability_found=true
            fi
            ;;
        
        # Общий анализ для других модулей
        *)
            if grep -qi "vulnerable\|exploitable\|password\|hash\|credential" "$log_file"; then
                vulnerability_details="$(grep -m1 -i 'vulnerable\|exploitable\|password\|hash\|credential' "$log_file" | head -c 200)"
                vulnerability_found=true
            elif grep -q '\[+\]' "$log_file"; then
                vulnerability_details="$(grep -m1 '\[+\]' "$log_file" | head -c 200)"
                vulnerability_found=true
            fi
            ;;
    esac
    
    if [[ "$vulnerability_found" == "true" ]]; then
        local timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
        local result_line="[$timestamp] $host | $module | $vulnerability_details"
        
        echo "$result_line" >> "$result_file"
        
        # Дублируем критические находки в общий файл
        if [[ "$priority" == "CRITICAL" ]]; then
            echo "$result_line" >> "$OUTPUT_DIR/CRITICAL_VULNERABILITIES.txt"
            log "ERROR" "CRITICAL VULNERABILITY: $host - $module - $vulnerability_details"
        fi
        
        log "SUCCESS" "Vulnerability found: $host/$module"
        return 0
    fi
    
    return 1
}

run_module_batch() {
    local modules=("$@")
    local priority="$1"
    local auth_required="${2:-false}"
    
    # Удаляем первые два параметра из массива модулей
    shift 2
    modules=("$@")
    
    log "INFO" "Running $priority priority modules (Auth required: $auth_required)"
    
    for module in "${modules[@]}"; do
        log "INFO" "Testing module: $module"
        
        # Определяем протокол по модулю
        local protocol="smb"
        case "$module" in
            ldap-checker|enum_trusts|adcs|pre2k) protocol="ldap" ;;
            rdp) protocol="rdp" ;;
            mssql_priv) protocol="mssql" ;;
            winrm*) protocol="winrm" ;;
            http*|web*) protocol="http" ;;
        esac
        
        # Проверяем, есть ли хосты для данного протокола
        local hosts_file="$OUTPUT_DIR/${protocol}_hosts.txt"
        if [[ ! -f "$hosts_file" ]] || [[ ! -s "$hosts_file" ]]; then
            log "WARN" "No $protocol hosts found for module $module"
            continue
        fi
        
        # Запускаем проверки параллельно
        local job_count=0
        while IFS= read -r host_line; do
            [[ -z "$host_line" ]] && continue
            
            # Извлекаем IP из формата "N|IP:port" 
            local host=$(echo "$host_line" | cut -d'|' -f2 | cut -d':' -f1)
            [[ -z "$host" ]] && continue
            
            run_vulnerability_check "$host" "$protocol" "$module" "$priority" "$auth_required" &
            
            ((job_count++))
            if ((job_count % MAX_PARALLEL == 0)); then
                wait # Ждём завершения батча
            fi
        done < "$hosts_file"
        
        wait # Ждём завершения всех заданий для текущего модуля
        
        # Создаём пустые файлы результатов если их нет
        touch "$OUTPUT_DIR/results/${priority}_${protocol}_${module}.txt"
    done
    
    log "SUCCESS" "$priority priority modules completed"
}

# ========================================================================
# ОСНОВНАЯ ЛОГИКА СКАНИРОВАНИЯ
# ========================================================================

run_unauthenticated_scan() {
    log "INFO" "Starting unauthenticated vulnerability scan"
    
    # Критические уязвимости (приоритет 1)
    run_module_batch "CRITICAL" false "${CRITICAL_MODULES[@]}"
    
    # Высокоприоритетные уязвимости (приоритет 2)
    run_module_batch "HIGH" false "${HIGH_MODULES[@]}"
    
    # Средние уязвимости (приоритет 3)
    run_module_batch "MEDIUM" false "${MEDIUM_MODULES[@]}"
    
    # Низкоприоритетные проверки (приоритет 4)
    run_module_batch "LOW" false "${LOW_MODULES[@]}"
    
    log "SUCCESS" "Unauthenticated scan completed"
}

run_authenticated_scan() {
    if [[ "$AUTHENTICATED_SCAN" != "true" ]]; then
        log "INFO" "Authenticated scan disabled, skipping"
        return
    fi
    
    log "INFO" "Starting authenticated vulnerability scan"
    if [[ -n "$DOMAIN" ]]; then
        log "INFO" "Using credentials: $USERNAME@$DOMAIN"
    else
        log "INFO" "Using credentials: $USERNAME (no domain)"
    fi
    
    # Проверяем credentials
    test_credentials || return 1
    
    # Запускаем модули, требующие аутентификации
    run_module_batch "AUTH" true "${AUTHENTICATED_MODULES[@]}"
    
    log "SUCCESS" "Authenticated scan completed"
}

test_credentials() {
    log "INFO" "Testing provided credentials"
    
    local test_host
    if [[ -f "$OUTPUT_DIR/smb_hosts.txt" ]] && [[ -s "$OUTPUT_DIR/smb_hosts.txt" ]]; then
        test_host=$(head -n1 "$OUTPUT_DIR/smb_hosts.txt" | cut -d'|' -f2 | cut -d':' -f1)
    else
        log "WARN" "No SMB hosts available for credential testing"
        return 1
    fi
    
    local test_cmd=("nxc" "smb" "$test_host" "-u" "$USERNAME" "-p" "$PASSWORD")
    if [[ -n "$DOMAIN" ]]; then
        test_cmd+=("-d" "$DOMAIN")
    fi
    
    if "${test_cmd[@]}" 2>/dev/null | grep -q "Pwn3d!\|[+]"; then
        log "SUCCESS" "Credentials validated successfully"
        return 0
    else
        log "ERROR" "Credential validation failed"
        return 1
    fi
}

# ========================================================================
# ГЕНЕРАЦИЯ ОТЧЁТОВ
# ========================================================================

generate_vulnerability_summary() {
    local summary_file="$OUTPUT_DIR/reports/vulnerability_summary.txt"
    
    log "INFO" "Generating vulnerability summary"
    
    cat > "$summary_file" << EOF
# AKUMA'S ADVANCED SCANNER - VULNERABILITY SUMMARY
# Generated: $(date)
# Scan directory: $OUTPUT_DIR
# Authentication: $([[ "$AUTHENTICATED_SCAN" == "true" ]] && echo "Enabled" || echo "Disabled")

===============================================================================
                            🔥 EXECUTIVE SUMMARY 🔥
===============================================================================

EOF
    
    # Подсчитываем уязвимости по приоритетам
    local critical_count=0
    local high_count=0
    local medium_count=0
    local low_count=0
    local auth_count=0
    
    if [[ -f "$OUTPUT_DIR/CRITICAL_VULNERABILITIES.txt" ]]; then
        critical_count=$(wc -l < "$OUTPUT_DIR/CRITICAL_VULNERABILITIES.txt")
    fi
    
    for priority in HIGH MEDIUM LOW AUTH; do
        local count=0
        for file in "$OUTPUT_DIR/results/${priority}"_*.txt; do
            [[ -f "$file" ]] && ((count += $(wc -l < "$file")))
        done
        
        case "$priority" in
            HIGH) high_count=$count ;;
            MEDIUM) medium_count=$count ;;
            LOW) low_count=$count ;;
            AUTH) auth_count=$count ;;
        esac
    done
    
    cat >> "$summary_file" << EOF
🚨 CRITICAL vulnerabilities found: $critical_count
⚠️  HIGH priority findings: $high_count  
📋 MEDIUM priority findings: $medium_count
📝 LOW priority findings: $low_count
🔐 AUTHENTICATED findings: $auth_count

TOTAL VULNERABILITIES: $((critical_count + high_count + medium_count + low_count + auth_count))

===============================================================================
                              🎯 HOST STATISTICS 🎯
===============================================================================

EOF
    
    # Статистика по хостам
    for service in smb ldap rdp mssql winrm http ftp ssh; do
        local hosts_file="$OUTPUT_DIR/${service}_hosts.txt"
        if [[ -f "$hosts_file" ]]; then
            local count=$(wc -l < "$hosts_file")
            echo "${service^^} hosts discovered: $count" >> "$summary_file"
        fi
    done
    
    echo "" >> "$summary_file"
    
    # Критические уязвимости детально
    if [[ -f "$OUTPUT_DIR/CRITICAL_VULNERABILITIES.txt" ]] && [[ -s "$OUTPUT_DIR/CRITICAL_VULNERABILITIES.txt" ]]; then
        cat >> "$summary_file" << EOF

===============================================================================
                        🔴 CRITICAL VULNERABILITIES 🔴
===============================================================================

EOF
        cat "$OUTPUT_DIR/CRITICAL_VULNERABILITIES.txt" >> "$summary_file"
    fi
    
    log "SUCCESS" "Vulnerability summary generated: $summary_file"
}

generate_detailed_report() {
    local report_file="$OUTPUT_DIR/reports/detailed_report.html"
    
    log "INFO" "Generating detailed HTML report"
    
    cat > "$report_file" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AKUMA's Advanced Scanner Report</title>
    <style>
        body { font-family: 'Courier New', monospace; background: #0a0a0a; color: #00ff00; margin: 0; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { text-align: center; border: 2px solid #00ff00; padding: 20px; margin-bottom: 30px; }
        .section { margin-bottom: 30px; border: 1px solid #333; padding: 15px; }
        .critical { background: #330000; border-color: #ff0000; }
        .high { background: #331a00; border-color: #ff6600; }
        .medium { background: #333300; border-color: #ffff00; }
        .low { background: #003333; border-color: #00ffff; }
        h1 { color: #ff0000; text-shadow: 0 0 10px #ff0000; }
        h2 { color: #00ff00; border-bottom: 1px solid #00ff00; }
        .vuln-item { margin: 10px 0; padding: 10px; background: rgba(0,255,0,0.1); }
        .timestamp { color: #666; font-size: 0.8em; }
        pre { background: #111; padding: 10px; overflow-x: auto; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }
        .stat-box { background: #111; padding: 15px; text-align: center; border: 1px solid #333; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔥 AKUMA'S ADVANCED SCANNER REPORT 🔥</h1>
            <p>"Your infrastructure just got PWNED by science"</p>
EOF

    echo "<p>Generated: $(date)</p>" >> "$report_file"
    echo "<p>Scan Directory: $OUTPUT_DIR</p>" >> "$report_file"
    echo "</div>" >> "$report_file"
    
    # Добавляем секции для каждого приоритета
    for priority in CRITICAL HIGH MEDIUM LOW AUTH; do
        local class_name=$(echo "$priority" | tr '[:upper:]' '[:lower:]')
        
        cat >> "$report_file" << EOF
        <div class="section $class_name">
            <h2>$priority Priority Findings</h2>
EOF
        
        local found_results=false
        for file in "$OUTPUT_DIR/results/${priority}"_*.txt; do
            if [[ -f "$file" ]] && [[ -s "$file" ]]; then
                found_results=true
                local module_name=$(basename "$file" .txt | sed "s/${priority}_//")
                echo "<h3>$module_name</h3>" >> "$report_file"
                echo "<pre>" >> "$report_file"
                cat "$file" >> "$report_file"
                echo "</pre>" >> "$report_file"
            fi
        done
        
        if [[ "$found_results" == "false" ]]; then
            echo "<p>No $priority priority vulnerabilities found. Your systems might be less fucked than expected.</p>" >> "$report_file"
        fi
        
        echo "</div>" >> "$report_file"
    done
    
    cat >> "$report_file" << 'EOF'
    </div>
</body>
</html>
EOF
    
    log "SUCCESS" "Detailed HTML report generated: $report_file"
}

cleanup_results() {
    log "INFO" "Cleaning up empty result files"
    
    # Удаляем пустые файлы результатов
    find "$OUTPUT_DIR/results" -type f -size 0 -delete 2>/dev/null || true
    find "$OUTPUT_DIR/logs" -type f -size -100c -delete 2>/dev/null || true
    
    # Архивируем логи если их много
    local log_count=$(find "$OUTPUT_DIR/logs" -type f | wc -l)
    if [[ $log_count -gt 100 ]]; then
        log "INFO" "Archiving logs ($log_count files)"
        tar -czf "$OUTPUT_DIR/logs_archive_$(date +%H%M%S).tar.gz" -C "$OUTPUT_DIR" logs/ 2>/dev/null
        rm -rf "$OUTPUT_DIR/logs"
        mkdir -p "$OUTPUT_DIR/logs"
    fi
    
    log "SUCCESS" "Cleanup completed"
}

# ========================================================================
# ОСНОВНАЯ ФУНКЦИЯ
# ========================================================================

main() {
    # Проверка прав и окружения
    if [[ $EUID -eq 0 ]]; then
        echo "[WARN] Running as root. Hope you know what you're doing, comrade!"
    fi
    
    # Показываем баннер
    show_banner
    
    # СНАЧАЛА загружаем конфигурацию (чтобы WORK_DIR был правильным)
    load_configuration
    
    # ПОТОМ создаём директории
    create_directories
    
    # Проверяем зависимости
    check_dependencies
    
    log "INFO" "Starting AKUMA's Advanced Low-Hanging Fruit Scanner"
    log "INFO" "Target subnets: ${SUBNETS[*]}"
    log "INFO" "Max parallel jobs: $MAX_PARALLEL"
    log "INFO" "Timeout per host: ${TIMEOUT_PER_HOST}s"
    
    # Обнаружение сервисов
    perform_service_discovery
    
    # Уязвимости без аутентификации
    run_unauthenticated_scan
    
    # Уязвимости с аутентификацией (если включено)
    run_authenticated_scan
    
    # Генерация отчётов
    generate_vulnerability_summary
    generate_detailed_report
    
    # Очистка
    cleanup_results
    
    log "SUCCESS" "Scan completed successfully!"
    echo ""
    echo -e "${GREEN}${BOLD}===============================================================================${NC}"
    echo -e "${GREEN}${BOLD}                    🔥 SCAN COMPLETED SUCCESSFULLY 🔥${NC}"
    echo -e "${GREEN}${BOLD}===============================================================================${NC}"
    echo ""
    echo -e "${CYAN}Results directory:${NC} $OUTPUT_DIR"
    echo -e "${CYAN}Summary report:${NC} $OUTPUT_DIR/reports/vulnerability_summary.txt"
    echo -e "${CYAN}HTML report:${NC} $OUTPUT_DIR/reports/detailed_report.html"
    echo ""
    
    # Показываем краткую статистику
    if [[ -f "$OUTPUT_DIR/CRITICAL_VULNERABILITIES.txt" ]]; then
        local critical_count=$(wc -l < "$OUTPUT_DIR/CRITICAL_VULNERABILITIES.txt")
        if [[ $critical_count -gt 0 ]]; then
            echo -e "${RED}${BOLD}🚨 $critical_count CRITICAL VULNERABILITIES FOUND! 🚨${NC}"
            echo -e "${RED}Your infrastructure is more fucked than a Windows ME installation!${NC}"
        fi
    fi
    
    echo ""
    echo -e "${PURPLE}Remember: With great power comes great responsibility... and potentially jail time.${NC}"
    echo -e "${PURPLE}                          - AKUMA 🔥${NC}"
}

# Обработка прерываний
trap 'echo -e "\n${RED}[INFO]${NC} Scan interrupted by user"; exit 130' INT TERM

# Опции командной строки
while [[ $# -gt 0 ]]; do
    case $1 in
        --auth)
            AUTHENTICATED_SCAN=true
            shift
            ;;
        --username)
            USERNAME="$2"
            shift 2
            ;;
        --password)
            PASSWORD="$2"
            shift 2
            ;;
        --domain)
            DOMAIN="$2"
            shift 2
            ;;
        --debug)
            DEBUG_MODE=true
            shift
            ;;
        --config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        --subnet)
            SUBNETS+=("$2")
            shift 2
            ;;
        --help|-h)
            echo "AKUMA's Advanced Low-Hanging Fruit Scanner"
            echo ""
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --auth              Enable authenticated scans"
            echo "  --username USER     Username for authentication"
            echo "  --password PASS     Password for authentication"
            echo "  --domain DOMAIN     Domain for authentication"
            echo "  --subnet SUBNET     Target subnet (can be used multiple times)"
            echo "  --debug             Enable debug mode"
            echo "  --config FILE       Use custom config file"
            echo "  --help, -h          Show this help"
            echo ""
            echo "Examples:"
            echo "  # Basic scan with subnet"
            echo "  $0 --subnet 192.168.1.0/24"
            echo ""
            echo "  # Authenticated scan with multiple subnets"
            echo "  $0 --auth --username admin --password 'P@ssw0rd' --domain CORP \\"
            echo "     --subnet 192.168.1.0/24 --subnet 10.0.0.0/16"
            exit 0
            ;;
        *)
            log "ERROR" "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Запуск основной функции
main "$@"
