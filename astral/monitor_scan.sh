#!/bin/bash

# ========================================================================
# AKUMA'S MASSIVE SCAN MONITOR - Мониторинг большого сканирования
# ========================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

SCAN_DIR="/home/akuma/Desktop/projects/astral"
LOG_FILE="$SCAN_DIR/massive_scan.log"

clear
echo -e "${RED}🔥 AKUMA'S MASSIVE SCAN MONITOR 🔥${NC}"
echo -e "${CYAN}Monitoring 60+ subnet corporate infrastructure scan${NC}"
echo ""

# Функция проверки статуса процесса
check_process() {
    if pgrep -f "mass_scan_config.conf" > /dev/null; then
        echo -e "${GREEN}✅ Scanner process: RUNNING${NC}"
        echo -e "${CYAN}   PID: $(pgrep -f mass_scan_config.conf)${NC}"
        return 0
    else
        echo -e "${RED}❌ Scanner process: STOPPED${NC}"
        return 1
    fi
}

# Функция показа прогресса
show_progress() {
    if [[ -f "$LOG_FILE" ]]; then
        echo -e "${YELLOW}📊 CURRENT PROGRESS:${NC}"
        echo ""
        
        # Последние строки лога
        echo -e "${CYAN}Last activity:${NC}"
        tail -n 5 "$LOG_FILE" | grep -E "\[(INFO|SUCCESS|WARN|ERROR)\]" | tail -n 3
        echo ""
        
        # Статистика найденных хостов
        local scan_dirs=($(find "$SCAN_DIR" -name "scan_*" -type d 2>/dev/null))
        if [[ ${#scan_dirs[@]} -gt 0 ]]; then
            local latest_scan="${scan_dirs[-1]}"
            echo -e "${CYAN}Hosts discovered so far:${NC}"
            
            for service in smb ldap rdp mssql winrm http ftp ssh; do
                local hosts_file="$latest_scan/${service}_hosts.txt"
                if [[ -f "$hosts_file" ]]; then
                    local count=$(wc -l < "$hosts_file" 2>/dev/null | tr -d '\n' || echo 0)
                    # Убираем любые лишние символы и пробелы
                    count=$(echo "$count" | tr -d ' \t\n\r')
                    if [[ "$count" =~ ^[0-9]+$ ]] && [[ $count -gt 0 ]]; then
                        echo -e "  ${service^^}: $count hosts"
                    fi
                fi
            done
            echo ""
        fi
        
        # Прогресс сканирования
        local total_services=10  # SMB, LDAP, RDP, etc.
        local completed_discoveries=$(grep -c "Found.*hosts" "$LOG_FILE" 2>/dev/null || echo 0)
        if [[ "$completed_discoveries" =~ ^[0-9]+$ ]] && [[ $completed_discoveries -gt 0 ]]; then
            local progress=$((completed_discoveries * 100 / total_services))
            if [[ $progress -gt 100 ]]; then progress=100; fi
            echo -e "${CYAN}Service discovery progress: ${progress}%${NC}"
        fi
        
        # Общая информация
        echo -e "${CYAN}Total IP addresses being scanned: 19,190${NC}"
    else
        echo -e "${YELLOW}📊 Log file not found yet...${NC}"
    fi
}

# Функция показа результатов
show_results() {
    local scan_dirs=($(find "$SCAN_DIR" -name "scan_*" -type d 2>/dev/null))
    if [[ ${#scan_dirs[@]} -gt 0 ]]; then
        local latest_scan="${scan_dirs[-1]}"
        echo -e "${YELLOW}📋 CURRENT RESULTS:${NC}"
        
        # Проверяем критические уязвимости
        local critical_file="$latest_scan/CRITICAL_VULNERABILITIES.txt"
        if [[ -f "$critical_file" ]] && [[ -s "$critical_file" ]]; then
            local critical_count=$(wc -l < "$critical_file" 2>/dev/null | tr -d '\n\t\r ' || echo 0)
            if [[ "$critical_count" =~ ^[0-9]+$ ]] && [[ $critical_count -gt 0 ]]; then
                echo -e "${RED}🚨 CRITICAL VULNERABILITIES: $critical_count${NC}"
                echo -e "${RED}Preview:${NC}"
                head -n 3 "$critical_file" | sed 's/^/  /'
                echo ""
            fi
        fi
        
        # Результаты по приоритетам
        for priority in HIGH MEDIUM LOW AUTH; do
            local count=0
            for file in "$latest_scan/results/${priority}"_*.txt; do
                if [[ -f "$file" ]] && [[ -s "$file" ]]; then
                    local file_count=$(wc -l < "$file" 2>/dev/null | tr -d '\n\t\r ' || echo 0)
                    if [[ "$file_count" =~ ^[0-9]+$ ]]; then
                        ((count += file_count))
                    fi
                fi
            done
            if [[ $count -gt 0 ]]; then
                echo -e "  $priority priority findings: $count"
            fi
        done
        
        echo ""
        echo -e "${CYAN}Results directory: $latest_scan${NC}"
    fi
}

# Основной цикл мониторинга
while true; do
    echo -e "\n${CYAN}========================================${NC}"
    echo -e "${CYAN}Scan Monitor - $(date)${NC}"
    echo -e "${CYAN}========================================${NC}\n"
    
    # Проверяем процесс
    if check_process; then
        show_progress
        show_results
        
        echo -e "\n${CYAN}Options:${NC}"
        echo -e "  ${YELLOW}[Enter]${NC} - Refresh"
        echo -e "  ${YELLOW}[l]${NC} - Show live log tail"  
        echo -e "  ${YELLOW}[k]${NC} - Kill scanner process"
        echo -e "  ${YELLOW}[r]${NC} - Show detailed results"
        echo -e "  ${YELLOW}[q]${NC} - Quit monitor"
        echo ""
        echo -n "Choice: "
        
        read -t 10 -n 1 choice
        case "$choice" in
            "l"|"L")
                echo -e "\n${CYAN}Live log (Press Ctrl+C to return):${NC}"
                tail -f "$LOG_FILE"
                ;;
            "k"|"K")
                echo -e "\n${RED}Killing scanner process...${NC}"
                pkill -f mass_scan_config.conf
                echo "Process terminated."
                exit 0
                ;;
            "r"|"R")
                show_results
                echo -e "\nPress Enter to continue..."
                read
                ;;
            "q"|"Q")
                echo -e "\n${GREEN}Exiting monitor...${NC}"
                exit 0
                ;;
        esac
        
    else
        echo -e "${YELLOW}Scanner has finished or crashed.${NC}"
        echo ""
        show_results
        echo -e "\nPress Enter to exit..."
        read
        exit 0
    fi
    
    clear
done
