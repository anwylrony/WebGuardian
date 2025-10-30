#!/bin/bash

# WebGuardian Scan Runner

TARGET_URL=$1
OUTPUT_DIR=${2:-"reports"}
CONFIG_FILE=${3:-"config.json"}

if [ -z "$TARGET_URL" ]; then
    echo "Usage: $0 <target_url> [output_dir] [config_file]"
    exit 1
fi

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Generate timestamp for report
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="$OUTPUT_DIR/scan_$(echo $TARGET_URL | sed 's/[^a-zA-Z0-9]/_/g')_$TIMESTAMP.json"

echo "[*] Starting WebGuardian scan on $TARGET_URL"
echo "[*] Report will be saved to $REPORT_FILE"

# Run the scan
cd /opt/webguardian
source bin/activate
python webguardian.py "$TARGET_URL" -c "$CONFIG_FILE" -o "$REPORT_FILE"

echo "[*] Scan completed. Report saved to $REPORT_FILE"
