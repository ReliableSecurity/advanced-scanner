#!/bin/bash

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# Функция безопасного подсчёта строк
safe_count() {
    local file="$1"
    if [[ -f "$file" && -s "$file" ]]; then
        wc -l < "$file" | tr -d ' '
    else
        echo "0"
    fi
}

# Функция поиска самой новой директории сканирования
find_latest_scan_dir() {
    local base_dir="/home/akuma/Desktop/projects"
    
    # Ищем папки, начинающиеся с scan_ или содержащие scanner.log
    local latest_dir=""
    local latest_time=0
    
    for dir in "$base_dir"/scan_* "$base_dir"/*/*/scan_*; do
        if [[ -d "$dir" && -f "$dir/scanner.log" ]]; then
            local dir_time=$(stat -c %Y "$dir" 2>/dev/null || echo 0)
            if [[ $dir_time -gt $latest_time ]]; then
                latest_time=$dir_time
                latest_dir="$dir"
            fi
        fi
    done
    
    echo "$latest_dir"
}

show_detailed_monitor() {
    local scan_dir="$1"
    
    clear
    echo -e "${RED}🔥 AKUMA'S SINGLE SUBNET MONITOR 🔥${NC}"
    echo -e "${PURPLE}Detailed monitoring for 192.168.112.0/24 scan${NC}"
    echo ""
    
    echo "========================================"
    echo -e "Scan Monitor - $(date)"
    echo "========================================"
    echo ""
    
    # Проверяем процесс сканера
    local scanner_pid=$(pgrep -f "advanced_lowhanging_scanner")
    if [[ -n "$scanner_pid" ]]; then
        echo -e "${GREEN}✅ Scanner process:${NC} RUNNING (PID: $scanner_pid)"
        local cpu_usage=$(ps -p "$scanner_pid" -o pcpu= 2>/dev/null | tr -d ' ')
        local mem_usage=$(ps -p "$scanner_pid" -o pmem= 2>/dev/null | tr -d ' ')
        echo -e "${CYAN}📊 Process stats:${NC} CPU: ${cpu_usage}%, RAM: ${mem_usage}%"
    else
        echo -e "${RED}❌ Scanner process:${NC} STOPPED"
        echo "Scanner has finished or crashed."
    fi
    echo ""
    
    # Анализируем результаты
    echo -e "${CYAN}📋 CURRENT RESULTS:${NC}"
    echo ""
    
    if [[ ! -d "$scan_dir" ]]; then
        echo -e "${RED}❌ Results directory not found: $scan_dir${NC}"
        return 1
    fi
    
    echo "Results directory: $scan_dir"
    echo ""
    
    # Проверяем логи
    local log_file="$scan_dir/scanner.log"
    if [[ -f "$log_file" ]]; then
        local log_lines=$(safe_count "$log_file")
        echo -e "${BLUE}📄 Log entries:${NC} $log_lines"
        
        # Показываем последние 3 строки лога
        echo -e "${YELLOW}Last activities:${NC}"
        tail -3 "$log_file" 2>/dev/null | sed 's/^/  /'
        echo ""
    fi
    
    # Статистика по найденным сервисам
    echo -e "${GREEN}🎯 DISCOVERED SERVICES:${NC}"
    local total_services=0
    for service in smb ldap rdp mssql winrm http ftp ssh telnet dns; do
        local hosts_file="$scan_dir/${service}_hosts.txt"
        local count=$(safe_count "$hosts_file")
        if [[ $count -gt 0 ]]; then
            echo -e "${WHITE}  ${service^^}:${NC} $count hosts"
            ((total_services += count))
        fi
    done
    echo -e "${CYAN}  TOTAL SERVICES:${NC} $total_services"
    echo ""
    
    # Проверяем уязвимости
    echo -e "${RED}🚨 VULNERABILITY STATUS:${NC}"
    
    # Критические уязвимости
    local critical_file="$scan_dir/CRITICAL_VULNERABILITIES.txt"
    local critical_count=$(safe_count "$critical_file")
    if [[ $critical_count -gt 0 ]]; then
        echo -e "${RED}⚠️  CRITICAL:${NC} $critical_count vulnerabilities found!"
        echo -e "${YELLOW}Details:${NC}"
        head -5 "$critical_file" 2>/dev/null | sed 's/^/  /'
    else
        echo -e "${GREEN}✅ CRITICAL:${NC} No critical vulnerabilities found"
    fi
    
    # Проверяем файлы результатов по приоритетам
    for priority in HIGH MEDIUM LOW AUTH; do
        local priority_count=0
        for result_file in "$scan_dir/results/${priority}"_*.txt; do
            if [[ -f "$result_file" ]]; then
                local file_count=$(safe_count "$result_file")
                ((priority_count += file_count))
            fi
        done
        
        if [[ $priority_count -gt 0 ]]; then
            echo -e "${YELLOW}📋 $priority:${NC} $priority_count findings"
        fi
    done
    echo ""
    
    # Проверяем ошибки
    echo -e "${PURPLE}🔍 ERROR ANALYSIS:${NC}"
    local error_files=("$scan_dir"/results/*.errors)
    local total_errors=0
    
    for error_file in "${error_files[@]}"; do
        if [[ -f "$error_file" ]]; then
            local error_count=$(safe_count "$error_file")
            ((total_errors += error_count))
        fi
    done
    
    if [[ $total_errors -gt 0 ]]; then
        echo -e "${YELLOW}⚠️  Total errors/timeouts:${NC} $total_errors"
        echo -e "${CYAN}Recent errors:${NC}"
        find "$scan_dir/results" -name "*.errors" -exec tail -2 {} \; 2>/dev/null | head -5 | sed 's/^/  /'
    else
        echo -e "${GREEN}✅ No errors detected${NC}"
    fi
    echo ""
    
    # Показываем прогресс если процесс активен
    if [[ -n "$scanner_pid" ]]; then
        echo -e "${CYAN}📈 SCAN PROGRESS:${NC}"
        
        # Анализируем текущую активность
        if [[ -f "$log_file" ]]; then
            local current_activity=$(tail -1 "$log_file" | grep -o '\[.*\]' | tail -1)
            echo -e "${WHITE}Current phase:${NC} $current_activity"
        fi
        
        # Показываем активные процессы NetExec
        local nxc_processes=$(pgrep -cf "nxc")
        echo -e "${WHITE}Active NetExec processes:${NC} $nxc_processes"
        
        echo ""
        echo -e "${GREEN}Scan is in progress... Press Ctrl+C to exit monitor.${NC}"
    else
        echo -e "${YELLOW}📊 SCAN COMPLETED${NC}"
        
        # Показываем итоговую статистику
        if [[ -d "$scan_dir/reports" ]]; then
            local report_count=$(find "$scan_dir/reports" -name "*.txt" -o -name "*.html" 2>/dev/null | wc -l)
            echo -e "${CYAN}📋 Generated reports:${NC} $report_count"
        fi
        
        echo ""
        echo -e "${GREEN}Use the following commands to analyze results:${NC}"
        echo -e "${CYAN}  View summary:${NC} cat $scan_dir/reports/vulnerability_summary.txt"
        echo -e "${CYAN}  View critical:${NC} cat $scan_dir/CRITICAL_VULNERABILITIES.txt"
        echo -e "${CYAN}  Open HTML report:${NC} xdg-open $scan_dir/reports/detailed_report.html"
    fi
    
    echo ""
}

main() {
    local scan_dir="${1:-}"
    
    # Если директория не указана, пытаемся найти автоматически
    if [[ -z "$scan_dir" ]]; then
        scan_dir=$(find_latest_scan_dir)
        if [[ -z "$scan_dir" ]]; then
            echo -e "${RED}❌ No scan directory found. Please provide path as argument.${NC}"
            exit 1
        fi
        echo -e "${CYAN}📁 Auto-detected scan directory:${NC} $scan_dir"
        echo ""
    fi
    
    # Проверяем существование директории
    if [[ ! -d "$scan_dir" ]]; then
        echo -e "${RED}❌ Directory does not exist: $scan_dir${NC}"
        exit 1
    fi
    
    # Показываем монитор
    show_detailed_monitor "$scan_dir"
    
    echo ""
    echo "Press Enter to refresh or Ctrl+C to exit..."
    read -r
    exec "$0" "$scan_dir"
}

# Обработчик прерывания
trap 'echo -e "\n${CYAN}Monitor stopped.${NC}"; exit 0' INT

main "$@"
