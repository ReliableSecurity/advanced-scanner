#!/bin/bash

# ========================================================================
# AKUMA'S DEMO SCANNER - Быстрая демонстрация возможностей
# ========================================================================

set -euo pipefail

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${RED}🔥 AKUMA'S DEMO SCANNER 🔥${NC}"
echo "Testing subnet: 192.168.112.0/22"
echo ""

# Создаём временную директорию
DEMO_DIR="/tmp/akuma_demo_$(date +%H%M%S)"
mkdir -p "$DEMO_DIR"

echo -e "${CYAN}[1/4]${NC} Discovering live hosts..."
nmap -sn --min-rate 1000 192.168.112.0/22 | grep "Nmap scan report" | awk '{print $5}' > "$DEMO_DIR/live_hosts.txt"
live_count=$(wc -l < "$DEMO_DIR/live_hosts.txt")
echo -e "${GREEN}Found $live_count live hosts${NC}"

echo -e "${CYAN}[2/4]${NC} Scanning for SSH services (port 22)..."
nmap -sT -p 22 --open --min-rate 1000 -iL "$DEMO_DIR/live_hosts.txt" | grep "Nmap scan report" | awk '{print $5}' > "$DEMO_DIR/ssh_hosts.txt"
ssh_count=$(wc -l < "$DEMO_DIR/ssh_hosts.txt")
echo -e "${GREEN}Found $ssh_count SSH hosts${NC}"

echo -e "${CYAN}[3/4]${NC} Testing SSH banner grabbing..."
if [[ $ssh_count -gt 0 ]]; then
    head -n5 "$DEMO_DIR/ssh_hosts.txt" | while read host; do
        echo -e "${YELLOW}Testing $host:${NC}"
        timeout 3 bash -c "echo '' | nc $host 22 2>/dev/null | head -n1" || echo "  - Connection failed"
    done
else
    echo -e "${YELLOW}No SSH hosts to test${NC}"
fi

echo -e "${CYAN}[4/4]${NC} Scanning for other services..."
echo "HTTP ports (80,443,8080):"
nmap -sT -p 80,443,8080 --open --min-rate 1000 -iL "$DEMO_DIR/live_hosts.txt" | grep -E "(Nmap scan report|open)" | head -n10

echo ""
echo -e "${GREEN}Demo completed! Results saved in: $DEMO_DIR${NC}"
ls -la "$DEMO_DIR"
