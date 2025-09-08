#!/bin/bash

# ========================================================================
# AKUMA'S VULNERABILITY TESTER - Быстрая проверка критических уязвимостей
# ========================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${RED}🔥 AKUMA'S VULNERABILITY TESTER 🔥${NC}"
echo ""

# Берём SMB хосты из результатов предыдущего сканирования
SMB_HOSTS_FILE="$HOME/lowhanging_results/scan_20250908_202858/smb_hosts.txt"

if [[ ! -f "$SMB_HOSTS_FILE" ]]; then
    echo -e "${RED}ERROR: SMB hosts file not found!${NC}"
    exit 1
fi

RESULTS_DIR="/tmp/akuma_vuln_$(date +%H%M%S)"
mkdir -p "$RESULTS_DIR"

echo -e "${CYAN}Testing CRITICAL vulnerabilities on $(wc -l < "$SMB_HOSTS_FILE") SMB hosts${NC}"
echo ""

# Функция для тестирования уязвимости
test_vulnerability() {
    local host=$1
    local vuln=$2
    local result_file="$RESULTS_DIR/${vuln}_results.txt"
    
    echo -e "${YELLOW}Testing $vuln on $host${NC}"
    
    # Запускаем тест с таймаутом
    if timeout 30 nxc smb "$host" -M "$vuln" 2>/dev/null | grep -E "(VULNERABLE|Vulnerable|vulnerable)" >> "$result_file"; then
        echo -e "${RED}  ⚠️  VULNERABLE TO $vuln!${NC}"
        echo "$host - VULNERABLE to $vuln" >> "$RESULTS_DIR/CRITICAL_FINDINGS.txt"
    else
        echo -e "  ✅ Not vulnerable to $vuln"
    fi
}

# Критические уязвимости для тестирования
CRITICAL_VULNS=("ms17-010" "zerologon" "smbghost" "printnightmare" "petitpotam")

# Тестируем каждую уязвимость на всех SMB хостах
for vuln in "${CRITICAL_VULNS[@]}"; do
    echo -e "${CYAN}=== Testing $vuln ===${NC}"
    
    while IFS= read -r host; do
        [[ -z "$host" ]] && continue
        test_vulnerability "$host" "$vuln"
    done < "$SMB_HOSTS_FILE"
    
    echo ""
done

echo -e "${GREEN}=== VULNERABILITY TEST RESULTS ===${NC}"
echo "Results directory: $RESULTS_DIR"

if [[ -f "$RESULTS_DIR/CRITICAL_FINDINGS.txt" ]]; then
    echo -e "${RED}🚨 CRITICAL VULNERABILITIES FOUND:${NC}"
    cat "$RESULTS_DIR/CRITICAL_FINDINGS.txt"
else
    echo "No critical vulnerabilities detected"
fi

echo ""
echo "Detailed results:"
ls -la "$RESULTS_DIR"
