#!/bin/bash

# ========================================================================
# AKUMA'S TEST SCAN MONITOR - Мониторинг тестового сканирования  
# ========================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

SCAN_DIR="/home/akuma/Desktop/projects/astral"
LOG_FILE="$SCAN_DIR/test_scan.log"

echo -e "${RED}🔥 AKUMA'S TEST SCAN MONITOR 🔥${NC}"
echo -e "${CYAN}Testing 4 subnets (1,784 hosts total)${NC}"
echo ""

# Проверка статуса
check_process() {
    if pgrep -f "test_scan_config.conf" > /dev/null; then
        echo -e "${GREEN}✅ Test scanner: RUNNING${NC}"
        echo -e "${CYAN}   PID: $(pgrep -f test_scan_config.conf)${NC}"
        return 0
    else
        echo -e "${RED}❌ Test scanner: STOPPED${NC}"
        return 1
    fi
}

# Показать текущий прогресс
show_progress() {
    if [[ -f "$LOG_FILE" ]]; then
        echo -e "${YELLOW}📊 CURRENT STATUS:${NC}"
        echo ""
        
        # Последняя активность
        local last_lines=$(tail -n 3 "$LOG_FILE" | grep -E "\[(INFO|SUCCESS|DEBUG|WARN|ERROR)\]" | tail -n 1)
        if [[ -n "$last_lines" ]]; then
            echo -e "${CYAN}Current activity:${NC}"
            echo "  $last_lines"
            echo ""
        fi
        
        # Найденные хосты
        local scan_dirs=($(find "$SCAN_DIR" -name "scan_*" -type d 2>/dev/null))
        if [[ ${#scan_dirs[@]} -gt 0 ]]; then
            local latest_scan="${scan_dirs[-1]}"
            echo -e "${CYAN}Hosts discovered:${NC}"
            
            local total_found=0
            for service in smb ldap rdp mssql winrm http ftp ssh telnet dns; do
                local hosts_file="$latest_scan/${service}_hosts.txt"
                if [[ -f "$hosts_file" ]]; then
                    local count=$(wc -l < "$hosts_file" 2>/dev/null | tr -d ' \n\t\r' || echo 0)
                    if [[ "$count" =~ ^[0-9]+$ ]] && [[ $count -gt 0 ]]; then
                        echo -e "  ${service^^}: $count hosts"
                        ((total_found += count))
                    fi
                fi
            done
            
            if [[ $total_found -gt 0 ]]; then
                echo -e "  ${YELLOW}TOTAL DISCOVERED: $total_found hosts${NC}"
            fi
            echo ""
        fi
        
        # Прогресс сервисов
        local services_completed=$(grep -c "Found.*hosts" "$LOG_FILE" 2>/dev/null || echo 0)
        if [[ "$services_completed" =~ ^[0-9]+$ ]] && [[ $services_completed -gt 0 ]]; then
            local progress=$((services_completed * 100 / 10))  # 10 сервисов всего
            echo -e "${CYAN}Service discovery progress: ${progress}%${NC}"
        fi
        
        # Уязвимости
        if [[ ${#scan_dirs[@]} -gt 0 ]]; then
            local latest_scan="${scan_dirs[-1]}"
            local vuln_count=0
            
            # Критические уязвимости
            local critical_file="$latest_scan/CRITICAL_VULNERABILITIES.txt"
            if [[ -f "$critical_file" ]] && [[ -s "$critical_file" ]]; then
                local critical_count=$(wc -l < "$critical_file" 2>/dev/null | tr -d ' \n\t\r' || echo 0)
                if [[ "$critical_count" =~ ^[0-9]+$ ]] && [[ $critical_count -gt 0 ]]; then
                    echo -e "${RED}🚨 CRITICAL VULNERABILITIES: $critical_count${NC}"
                    ((vuln_count += critical_count))
                fi
            fi
            
            # Остальные уязвимости
            for priority in HIGH MEDIUM LOW; do
                local count=0
                for file in "$latest_scan/results/${priority}"_*.txt; do
                    if [[ -f "$file" ]] && [[ -s "$file" ]]; then
                        local file_count=$(wc -l < "$file" 2>/dev/null | tr -d ' \n\t\r' || echo 0)
                        if [[ "$file_count" =~ ^[0-9]+$ ]]; then
                            ((count += file_count))
                        fi
                    fi
                done
                if [[ $count -gt 0 ]]; then
                    echo -e "  $priority priority: $count findings"
                    ((vuln_count += count))
                fi
            done
            
            if [[ $vuln_count -gt 0 ]]; then
                echo -e "${YELLOW}Total vulnerabilities found so far: $vuln_count${NC}"
            fi
        fi
    else
        echo -e "${YELLOW}Log file not found yet...${NC}"
    fi
}

# Основная функция
main() {
    while true; do
        clear
        echo -e "${RED}🔥 AKUMA'S TEST SCAN MONITOR 🔥${NC}"
        echo -e "${CYAN}Testing: 192.168.112.0/22, 192.168.180.0/24, 192.168.12.0/24, 10.0.13.0/24${NC}"
        echo -e "${CYAN}Total: 1,784 IP addresses${NC}"
        echo ""
        echo -e "${CYAN}========================================${NC}"
        echo -e "${CYAN}Monitor Update - $(date)${NC}"
        echo -e "${CYAN}========================================${NC}"
        echo ""
        
        if check_process; then
            show_progress
            echo ""
            echo -e "${CYAN}Options: [Enter]=Refresh [l]=Live Log [k]=Kill [q]=Quit${NC}"
            
            read -t 15 -n 1 choice
            case "$choice" in
                "l"|"L")
                    echo -e "\n${CYAN}Live log tail (Ctrl+C to return):${NC}"
                    tail -f "$LOG_FILE"
                    ;;
                "k"|"K")
                    echo -e "\n${RED}Killing test scanner...${NC}"
                    pkill -f test_scan_config.conf
                    echo "Process terminated."
                    exit 0
                    ;;
                "q"|"Q")
                    echo -e "\n${GREEN}Exiting monitor...${NC}"
                    exit 0
                    ;;
            esac
        else
            echo -e "${YELLOW}Test scan completed or stopped.${NC}"
            show_progress
            echo -e "\nPress Enter to exit..."
            read
            exit 0
        fi
    done
}

main
