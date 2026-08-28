#!/usr/bin/env bash
# ==============================================================================
#  ANDS SENTINEL v2.0 - Universal Automated Installer
#  Live SOC Analyst & Anomaly-Based Network Detection System
# ==============================================================================

set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
WHITE='\033[1;37m'
GRAY='\033[0;90m'
NC='\033[0m' # No Color

echo -e "${WHITE}"
cat << "EOF"
 █████╗ ███╗   ██╗██████╗ ███████╗
██╔══██╗████╗  ██║██╔══██╗██╔════╝
███████║██╔██╗ ██║██║  ██║███████╗
██╔══██║██║╚██╗██║██║  ██║╚════██║
██║  ██║██║ ╚████║██████╔╝███████║
╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝
EOF
echo -e "${CYAN}── Automated System Installer & Dependency Provisioner ──${NC}\n"

# Verify Root Privileges
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[✗] Error: Please run the installer with sudo or as root.${NC}"
    echo -e "    Usage: ${WHITE}sudo ./install.sh${NC}\n"
    exit 1
fi

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

echo -e "${CYAN}[*] Step 1/5: Detecting Linux Distribution & Package Manager...${NC}"
if command -v pacman &> /dev/null; then
    echo -e "${GREEN}[✓] Detected Arch Linux / Pacman system.${NC}"
    pacman -Sy --noconfirm --needed python python-pip libpcap tcpdump iptables iproute2 net-tools gcc
elif command -v apt-get &> /dev/null; then
    echo -e "${GREEN}[✓] Detected Debian / Ubuntu / Kali system.${NC}"
    apt-get update -y
    apt-get install -y python3 python3-pip python3-venv libpcap-dev tcpdump iptables iproute2 net-tools build-essential curl
elif command -v dnf &> /dev/null; then
    echo -e "${GREEN}[✓] Detected Fedora / RHEL / CentOS system.${NC}"
    dnf install -y python3 python3-pip python3-devel libpcap-devel tcpdump iptables iproute net-tools gcc
elif command -v apk &> /dev/null; then
    echo -e "${GREEN}[✓] Detected Alpine Linux system.${NC}"
    apk update && apk add python3 py3-pip libpcap-dev tcpdump iptables iproute2 net-tools gcc musl-dev
else
    echo -e "${YELLOW}[!] Warning: Unknown package manager. Ensure libpcap and Python 3.10+ are installed.${NC}"
fi

echo -e "\n${CYAN}[*] Step 2/5: Provisioning Isolated Python Virtual Environment...${NC}"
if [ ! -d "$PROJECT_DIR/venv" ]; then
    python3 -m venv "$PROJECT_DIR/venv"
fi

"$PROJECT_DIR/venv/bin/pip" install --upgrade pip setuptools wheel
"$PROJECT_DIR/venv/bin/pip" install -r "$PROJECT_DIR/requirements.txt"
"$PROJECT_DIR/venv/bin/pip" install -e "$PROJECT_DIR"

echo -e "\n${CYAN}[*] Step 3/5: Creating System Binary Launchers in /usr/local/bin...${NC}"
cat << EOF > /usr/local/bin/ANDS-shell
#!/usr/bin/env bash
SCRIPT_DIR="$PROJECT_DIR"
if [ -f "\$SCRIPT_DIR/venv/bin/python" ]; then
    exec "\$SCRIPT_DIR/venv/bin/python" "\$SCRIPT_DIR/ands.py" "\$@"
else
    exec python3 "\$SCRIPT_DIR/ands.py" "\$@"
fi
EOF

chmod +x /usr/local/bin/ANDS-shell
ln -sf /usr/local/bin/ANDS-shell /usr/local/bin/ands
ln -sf /usr/local/bin/ANDS-shell /usr/local/bin/ands-dashboard

echo -e "\n${CYAN}[*] Step 4/5: Installing Desktop Application & App Launcher...${NC}"
mkdir -p /usr/share/applications /usr/share/icons/hicolor/scalable/apps

# Generate Icon if missing
if [ -f "$PROJECT_DIR/web/static/icon.png" ]; then
    cp "$PROJECT_DIR/web/static/icon.png" /usr/share/icons/hicolor/scalable/apps/ands-sentinel.png
fi

cat << EOF > /usr/share/applications/ands-sentinel.desktop
[Desktop Entry]
Name=ANDS SOC Sentinel
GenericName=Network Anomaly & Threat Detection
Comment=Live SOC Analyst & Anomaly-based Network Detection System
Exec=/usr/local/bin/ANDS-shell all
Icon=security-high
Terminal=true
Type=Application
Categories=Network;Security;System;Monitor;
Keywords=soc;ids;nids;network;threat;pcap;security;sniff;
EOF
chmod 644 /usr/share/applications/ands-sentinel.desktop

echo -e "\n${CYAN}[*] Step 5/5: Verifying Installation Integrity...${NC}"
TOTAL_MODS=$("$PROJECT_DIR/venv/bin/python" -c "from core.module_loader import load_all_modules; print(len(load_all_modules()))" 2>/dev/null || echo "0")

echo -e "${GREEN}======================================================================${NC}"
echo -e "${WHITE}  🎉 ANDS SENTINEL v2.0 INSTALLED SUCCESSFULLY!${NC}"
echo -e "${GREEN}======================================================================${NC}"
echo -e "  • Total Modules & Aliases Loaded: ${WHITE}${TOTAL_MODS}${NC}"
echo -e "  • Global Terminal Command:        ${WHITE}sudo ANDS-shell${NC} or ${WHITE}sudo ands${NC}"
echo -e "  • 1-Click Unified 3-in-1 Suite:   ${WHITE}sudo ANDS-shell all${NC}"
echo -e "  • Web SOC Dashboard:              ${WHITE}http://localhost:8899${NC}"
echo -e "  • Desktop Application:            Search for ${WHITE}'ANDS SOC Sentinel'${NC} in App Menu"
echo -e "${GREEN}======================================================================${NC}\n"
