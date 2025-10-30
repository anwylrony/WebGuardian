#!/bin/bash

# WebGuardian Setup Script

echo "[*] WebGuardian Setup Script"
echo "[*] This script will install WebGuardian and its dependencies"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (use sudo)"
  exit 1
fi

# Update package lists
echo "[*] Updating package lists..."
apt-get update

# Install dependencies
echo "[*] Installing dependencies..."
apt-get install -y python3 python3-pip python3-venv build-essential libjsoncpp-dev openssl curl

# Create virtual environment
echo "[*] Creating Python virtual environment..."
python3 -m venv /opt/webguardian
source /opt/webguardian/bin/activate

# Install Python dependencies
echo "[*] Installing Python dependencies..."
pip install requests beautifulsoup4 lxml

# Compile C++ modules
echo "[*] Compiling C++ modules..."
cd cpp
make install
cd ..

# Create directories
echo "[*] Creating directories..."
mkdir -p data/payloads data/signatures reports

# Download common payloads
echo "[*] Downloading common payloads..."
curl -s https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/data/txt/wordlist.txt -o data/payloads/common.txt

# Create default configuration
echo "[*] Creating default configuration..."
cat > config.json << EOF
{
    "threads": 10,
    "delay": 0.5,
    "timeout": 10,
    "max_depth": 3,
    "user_agents": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
    ],
    "payloads_file": "data/payloads/common.txt",
    "signatures_file": "data/signatures/vulns.json"
}
EOF

# Create launcher script
echo "[*] Creating launcher script..."
cat > /usr/local/bin/webguardian << 'EOF'
#!/bin/bash
cd /opt/webguardian
source bin/activate
python webguardian.py "$@"
EOF

chmod +x /usr/local/bin/webguardian

echo "[*] Installation complete!"
echo "[*] Run 'webguardian --help' for usage information"
echo "[*] Remember to only use WebGuardian on systems you have permission to test"
