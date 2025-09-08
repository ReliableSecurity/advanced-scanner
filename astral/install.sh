#!/bin/bash

# 🔥 AKUMA's Advanced Scanner - Installation Script
# "If your system survives this installer, it might survive our scanner too"

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_LOG="/tmp/akuma_install.log"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${RED}"
cat << "EOF"
╔══════════════════════════════════════════════════════════════════════════════╗
║                🔥 AKUMA SCANNER INSTALLATION 🔥                               ║
║               "Installing tools to pwn the world"                            ║
╚══════════════════════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}\n"

log() {
    echo -e "${GREEN}[$(date '+%H:%M:%S')]${NC} $1" | tee -a "$INSTALL_LOG"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$INSTALL_LOG"
    exit 1
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root (use sudo)"
    fi
}

install_dependencies() {
    log "Installing system dependencies..."
    
    # Update package list
    apt-get update -y >> "$INSTALL_LOG" 2>&1
    
    # Install required packages
    local packages=(
        "nmap"
        "masscan"
        "python3"
        "python3-pip"
        "curl"
        "wget"
        "git"
        "smbclient"
        "enum4linux"
        "ldap-utils"
        "dnsutils"
        "netcat-openbsd"
    )
    
    for package in "${packages[@]}"; do
        log "Installing $package..."
        apt-get install -y "$package" >> "$INSTALL_LOG" 2>&1 || {
            error "Failed to install $package"
        }
    done
}

install_netexec() {
    log "Installing NetExec (the heart of AKUMA)..."
    
    # Install via pipx (recommended way)
    if ! command -v pipx &>/dev/null; then
        log "Installing pipx first..."
        apt-get install -y pipx >> "$INSTALL_LOG" 2>&1
        pipx ensurepath
    fi
    
    # Install NetExec
    pipx install git+https://github.com/Pennyw0rth/NetExec >> "$INSTALL_LOG" 2>&1 || {
        log "Trying alternative installation method..."
        pip3 install git+https://github.com/Pennyw0rth/NetExec >> "$INSTALL_LOG" 2>&1 || {
            error "Failed to install NetExec"
        }
    }
    
    # Create symlink for backward compatibility
    if command -v netexec &>/dev/null; then
        ln -sf "$(which netexec)" /usr/local/bin/nxc 2>/dev/null || true
    fi
}

setup_scanner() {
    log "Setting up AKUMA scanner files..."
    
    # Make scripts executable
    chmod +x "$SCRIPT_DIR/akuma_scanner.sh" || error "Failed to make akuma_scanner.sh executable"
    chmod +x "$SCRIPT_DIR/knowledge_base.sh" || error "Failed to make knowledge_base.sh executable"
    
    # Create default directories
    mkdir -p /opt/akuma_scanner
    mkdir -p ~/lowhanging_results
    
    # Copy scripts to system location (optional)
    cp "$SCRIPT_DIR/akuma_scanner.sh" /opt/akuma_scanner/ 2>/dev/null || true
    cp "$SCRIPT_DIR/knowledge_base.sh" /opt/akuma_scanner/ 2>/dev/null || true
    
    # Create symlink for global access
    ln -sf "$SCRIPT_DIR/akuma_scanner.sh" /usr/local/bin/akuma-scan 2>/dev/null || true
    
    log "AKUMA scanner installed to /opt/akuma_scanner/"
}

verify_installation() {
    log "Verifying installation..."
    
    local required_commands=("nmap" "python3")
    local missing=()
    
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    
    # Check NetExec specifically
    if ! command -v netexec &>/dev/null && ! command -v nxc &>/dev/null; then
        missing+=("netexec")
    fi
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        error "Installation verification failed. Missing: ${missing[*]}"
    fi
    
    log "✅ All dependencies verified successfully!"
}

main() {
    log "Starting AKUMA Scanner installation..."
    
    check_root
    install_dependencies
    install_netexec  
    setup_scanner
    verify_installation
    
    echo -e "\n${GREEN}🎉 INSTALLATION COMPLETED SUCCESSFULLY! 🎉${NC}\n"
    echo -e "${YELLOW}Usage examples:${NC}"
    echo "  ./akuma_scanner.sh 192.168.1.0/24"
    echo "  ./akuma_scanner.sh targets.txt -c enterprise_config.conf"
    echo "  akuma-scan 10.0.0.0/16  # Global command"
    echo ""
    echo -e "${YELLOW}Next steps:${NC}"
    echo "1. Edit configuration: nano scanner_config.conf"
    echo "2. Run your first scan: ./akuma_scanner.sh --help"
    echo ""
    echo -e "${RED}⚠️  Remember: Use only on authorized networks!${NC}"
    
    log "Installation completed successfully"
}

main "$@"
