#!/bin/bash

# 🎯 AKUMA Scanner v2.0 - Quick Demo Script
# Демонстрация основных возможностей сканера

echo "🔥 AKUMA Advanced Scanner v2.0 - DEMO"
echo "=====================================\n"

# Показать версию и основные файлы
echo "📋 Core Files:"
ls -la akuma_scanner.sh knowledge_base.sh install.sh *.conf | head -5

echo -e "\n📊 Recent Scan Results:"
if [ -d "scan_"* ] 2>/dev/null; then
    latest_scan=$(ls -td scan_*/ | head -1)
    echo "Latest scan directory: $latest_scan"
    
    echo -e "\n🎯 Services Discovered:"
    for file in ${latest_scan}*_hosts.txt; do
        if [ -f "$file" ]; then
            service_name=$(basename "$file" _hosts.txt)
            count=$(wc -l < "$file" 2>/dev/null || echo "0")
            echo "• $service_name: $count hosts"
        fi
    done
    
    echo -e "\n📝 Sample Results:"
    for file in ${latest_scan}*_hosts.txt; do
        if [ -f "$file" ] && [ -s "$file" ]; then
            service_name=$(basename "$file" _hosts.txt)
            echo -e "\n--- $service_name services ---"
            head -3 "$file"
            break
        fi
    done
else
    echo "No recent scans found. Run a demo scan:"
    echo "./akuma_scanner.sh 192.168.1.1/32"
fi

echo -e "\n🚀 Key Features:"
echo "• ✅ Enterprise scalability (100+ subnets)"
echo "• ✅ Checkpoint system for resume capability"  
echo "• ✅ IP:Port format in all outputs"
echo "• ✅ Vulnerability knowledge base integration"
echo "• ✅ Three report formats (TXT/HTML/Exploit Guide)"
echo "• ✅ Robust error handling with retries"
echo "• ✅ Parallel processing optimization"

echo -e "\n📖 Quick Commands:"
echo "Basic scan:      ./akuma_scanner.sh 192.168.1.0/24"
echo "Enterprise:      ./akuma_scanner.sh targets.txt -c enterprise_config.conf"
echo "Resume scan:     ./akuma_scanner.sh --resume /tmp/akuma_scanner_checkpoints/"
echo "With exploits:   ./akuma_scanner.sh 10.0.0.0/16 --enable-exploits"

echo -e "\n⚠️  Remember: Use only in authorized environments!"
echo "🎉 Ready for production deployment!"
