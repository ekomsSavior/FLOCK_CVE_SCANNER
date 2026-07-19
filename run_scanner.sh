#!/bin/bash
# Run scanner with proper Shodan queries

echo "CVE-2025 Scanner with Shodan Integration"
echo "========================================"
echo ""

# Generate queries
echo "Generating Shodan queries..."
python3 shodan_queries.py

echo ""
echo "Select option:"
echo "1. Run scanner with Shodan auto-query"
echo "2. Run scanner with manual IP"
echo "3. Run scanner with file"

read -p "Choice (1-3): " choice

case $choice in
    1)
        echo "Running scanner with Shodan..."
        # Use the scanner with a specific query
        python3 scanner.py -v
        ;;
    2)
        read -p "Enter IP: " ip
        python3 scanner.py -t $ip --exploit
        ;;
    3)
        read -p "Enter file: " file
        python3 scanner.py -f $file
        ;;
esac
