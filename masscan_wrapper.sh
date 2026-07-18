#!/bin/bash
# masscan_wrapper.sh - Use masscan to find targets

echo "CVE-2025 Masscan Wrapper"
echo "========================"

# Common ports for vulnerable services
PORTS="80,443,5555,5037,8080,8443,9000,8443"

echo "Running masscan for ports: $PORTS"
sudo masscan -p$PORTS --rate=1000 -oJ masscan_results.json 0.0.0.0/0

echo "Extracting IPs..."
cat masscan_results.json | jq -r '.[] | .ip' > targets.txt

echo "Found $(wc -l < targets.txt) targets"
echo "Now scanning targets with CVE scanner..."
python3 cve_scanner.py -f targets.txt -o results.json
