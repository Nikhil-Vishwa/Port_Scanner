#!/usr/bin/env python3
"""
Professional Port Scanner Suite
A comprehensive, multi-threaded port scanner with advanced features
"""

import socket
import subprocess
import sys
import argparse
import json
import csv
import re
import time
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Dict, Optional, Callable, Tuple

# Try to import optional dependencies
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False
    # Fallback color class
    class Fore:
        RED = GREEN = YELLOW = BLUE = CYAN = MAGENTA = WHITE = RESET = ''
    class Style:
        BRIGHT = DIM = RESET_ALL = ''

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

try:
    from scapy.all import sr, IP, TCP, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# ============================================================================
# CONFIGURATION
# ============================================================================

class Config:
    """Configuration settings for the scanner"""
    
    # Default scanning parameters
    DEFAULT_TIMEOUT = 0.5
    DEFAULT_THREADS = 50
    MAX_THREADS = 200
    
    # Scan profiles
    SCAN_PROFILES = {
        'quick': {
            'name': 'Quick Scan',
            'description': 'Scan most common ports (top 100)',
            'ports': [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 
                      1433, 1521, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017,
                      20, 69, 111, 123, 137, 138, 161, 162, 389, 465, 514, 587, 636,
                      1080, 1194, 2049, 2082, 2083, 2181, 2375, 2376, 3000, 3128, 3268,
                      3269, 4443, 4444, 5000, 5001, 5222, 5269, 5432, 5555, 5672, 5984,
                      6000, 6001, 6379, 7000, 7001, 7077, 8000, 8001, 8008, 8081, 8082,
                      8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8888, 9000, 9001,
                      9090, 9091, 9092, 9200, 9300, 9443, 10000, 11211, 15672, 27018, 50000],
            'timeout': 0.3,
            'threads': 100,
        },
        'normal': {
            'name': 'Normal Scan',
            'description': 'Scan well-known ports (1-1024)',
            'ports': range(1, 1025),
            'timeout': 0.5,
            'threads': 50,
        },
        'deep': {
            'name': 'Deep Scan',
            'description': 'Comprehensive scan (1-65535)',
            'ports': range(1, 65536),
            'timeout': 1.0,
            'threads': 100,
        },
    }
    
    # Common services mapping
    COMMON_SERVICES = {
        20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
        53: 'DNS', 67: 'DHCP', 69: 'TFTP', 80: 'HTTP', 110: 'POP3',
        123: 'NTP', 135: 'MS-RPC', 137: 'NetBIOS', 139: 'NetBIOS', 143: 'IMAP',
        161: 'SNMP', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS',
        514: 'Syslog', 587: 'SMTP', 636: 'LDAPS', 993: 'IMAPS', 995: 'POP3S',
        1433: 'MS-SQL', 1521: 'Oracle', 1723: 'PPTP', 3306: 'MySQL', 3389: 'RDP',
        5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Proxy',
        8443: 'HTTPS-Alt', 27017: 'MongoDB', 27018: 'MongoDB'
    }


# ============================================================================
# SERVICE DETECTION & BANNER GRABBING
# ============================================================================

class ServiceDetector:
    """Detect services and grab banners from open ports"""
    
    # Protocol-specific probes
    PROBES = {
        'http': b'GET / HTTP/1.0\r\n\r\n',
        'smtp': b'EHLO scanner\r\n',
        'ftp': b'',
        'ssh': b'',
        'pop3': b'',
        'imap': b'',
        'redis': b'INFO\r\n',
    }
    
    # Service signatures
    SIGNATURES = {
        rb'HTTP/\d\.\d': 'HTTP',
        rb'SSH-(\d+\.\d+)': 'SSH',
        rb'220[- ].*FTP': 'FTP',
        rb'220[- ].*SMTP': 'SMTP',
        rb'\+OK.*POP3': 'POP3',
        rb'\* OK.*IMAP': 'IMAP',
        rb'redis_version': 'Redis',
        rb'MySQL': 'MySQL',
        rb'PostgreSQL': 'PostgreSQL',
        rb'MongoDB': 'MongoDB',
    }
    
    def __init__(self, timeout: float = 2.0):
        self.timeout = timeout
    
    def detect(self, target_ip: str, port: int) -> Tuple[str, Optional[str], Optional[str]]:
        """
        Detect service and grab banner
        
        Returns:
            Tuple of (service_name, version, banner)
        """
        default_service = Config.COMMON_SERVICES.get(port, 'Unknown')
        banner = self._grab_banner(target_ip, port)
        
        if banner:
            service, version = self._analyze_banner(banner, default_service)
            return service, version, banner
        
        return default_service, None, None
    
    def _grab_banner(self, target_ip: str, port: int) -> Optional[str]:
        """Grab banner from a port"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        
        try:
            sock.connect((target_ip, port))
            
            # Send probe if applicable
            probe = self._get_probe(port)
            if probe:
                sock.send(probe)
            
            # Receive response
            banner = sock.recv(4096)
            if banner:
                try:
                    return banner.decode('utf-8').strip()
                except UnicodeDecodeError:
                    return banner.decode('latin-1', errors='ignore').strip()
        except:
            pass
        finally:
            sock.close()
        
        return None
    
    def _get_probe(self, port: int) -> bytes:
        """Get appropriate probe for a service"""
        port_probe_map = {
            80: 'http', 8080: 'http', 8443: 'http', 443: 'http',
            21: 'ftp', 22: 'ssh', 25: 'smtp', 110: 'pop3',
            143: 'imap', 6379: 'redis'
        }
        probe_type = port_probe_map.get(port)
        return self.PROBES.get(probe_type, b'')
    
    def _analyze_banner(self, banner: str, default: str) -> Tuple[str, Optional[str]]:
        """Analyze banner to detect service and version"""
        banner_bytes = banner.encode('utf-8', errors='ignore')
        
        for pattern, service in self.SIGNATURES.items():
            if re.search(pattern, banner_bytes):
                version = self._extract_version(banner)
                return service, version
        
        return default, self._extract_version(banner)
    
    def _extract_version(self, banner: str) -> Optional[str]:
        """Extract version from banner"""
        patterns = [
            r'version[:\s]+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            r'v([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            r'([0-9]+\.[0-9]+\.[0-9]+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None


# ============================================================================
# VULNERABILITY DETECTION
# ============================================================================

class VulnerabilityScanner:
    """Basic vulnerability detection"""
    
    VULNERABILITIES = {
        21: {
            'check': 'anonymous_ftp',
            'title': 'Anonymous FTP Access',
            'severity': 'medium',
            'description': 'FTP server may allow anonymous access'
        },
        23: {
            'check': 'telnet_open',
            'title': 'Telnet Service Running',
            'severity': 'high',
            'description': 'Telnet transmits data in cleartext'
        },
        3306: {
            'check': 'mysql_open',
            'title': 'MySQL Exposed',
            'severity': 'medium',
            'description': 'MySQL database is accessible from network'
        },
        6379: {
            'check': 'redis_open',
            'title': 'Redis Exposed',
            'severity': 'high',
            'description': 'Redis server may be unprotected'
        },
        27017: {
            'check': 'mongodb_open',
            'title': 'MongoDB Exposed',
            'severity': 'high',
            'description': 'MongoDB database is accessible from network'
        }
    }
    
    def scan(self, port: int, service: str, banner: str) -> List[Dict]:
        """Scan for vulnerabilities on a port"""
        vulns = []
        
        if port in self.VULNERABILITIES:
            vuln = self.VULNERABILITIES[port].copy()
            vuln['port'] = port
            vuln['service'] = service
            vulns.append(vuln)
        
        # Check for outdated versions
        if banner and 'version' in banner.lower():
            if any(old in banner.lower() for old in ['5.5', '5.6', '1.0', '2.0']):
                vulns.append({
                    'port': port,
                    'service': service,
                    'title': 'Potentially Outdated Version',
                    'severity': 'low',
                    'description': f'Service may be running an outdated version'
                })
        
        return vulns


# ============================================================================
# PORT SCANNER ENGINE
# ============================================================================

class PortScanner:
    """Multi-threaded port scanner with advanced features"""
    
    def __init__(self, target: str, ports: List[int], scan_type: str = 'tcp',
                 timeout: float = None, threads: int = None,
                 service_detection: bool = True, banner_grabbing: bool = False,
                 vuln_scan: bool = False, progress_callback: Optional[Callable] = None):
        """
        Initialize the scanner
        
        Args:
            target: Target IP address or hostname
            ports: List of ports to scan
            scan_type: Type of scan (tcp, udp, syn)
            timeout: Socket timeout in seconds
            threads: Number of concurrent threads
            service_detection: Enable service detection
            banner_grabbing: Enable banner grabbing
            vuln_scan: Enable vulnerability scanning
            progress_callback: Callback for progress updates
        """
        self.target = target
        self.ports = list(ports) if not isinstance(ports, list) else ports
        self.scan_type = scan_type.lower()
        self.timeout = timeout or Config.DEFAULT_TIMEOUT
        self.threads = min(threads or Config.DEFAULT_THREADS, Config.MAX_THREADS)
        self.service_detection = service_detection
        self.banner_grabbing = banner_grabbing
        self.vuln_scan = vuln_scan
        self.progress_callback = progress_callback
        
        # Results storage
        self.results = []
        self.open_ports = []
        self.vulnerabilities = []
        
        # Control flags
        self.cancelled = False
        self.lock = threading.Lock()
        
        # Statistics
        self.scanned_count = 0
        self.total_ports = len(self.ports)
        self.start_time = None
        self.end_time = None
        
        # Initialize detectors
        self.service_detector = ServiceDetector() if banner_grabbing else None
        self.vuln_scanner = VulnerabilityScanner() if vuln_scan else None
        
        # Resolve target
        try:
            self.target_ip = socket.gethostbyname(self.target)
        except socket.gaierror:
            raise ValueError(f"Cannot resolve hostname: {self.target}")
    
    def scan(self) -> Dict:
        """Execute the port scan"""
        self.start_time = datetime.now()
        
        self._print_banner()
        
        if self.scan_type == 'tcp':
            self._tcp_scan()
        elif self.scan_type == 'udp':
            self._udp_scan()
        elif self.scan_type == 'syn':
            self._syn_scan()
        else:
            raise ValueError(f"Unsupported scan type: {self.scan_type}")
        
        self.end_time = datetime.now()
        
        return self._compile_results()
    
    def _print_banner(self):
        """Print scan banner"""
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}Professional Port Scanner")
        print(f"{Fore.CYAN}{'='*70}")
        print(f"{Fore.YELLOW}Target: {Fore.WHITE}{self.target} ({self.target_ip})")
        print(f"{Fore.YELLOW}Scan Type: {Fore.WHITE}{self.scan_type.upper()}")
        print(f"{Fore.YELLOW}Ports: {Fore.WHITE}{self.total_ports}")
        print(f"{Fore.YELLOW}Threads: {Fore.WHITE}{self.threads}")
        print(f"{Fore.YELLOW}Service Detection: {Fore.WHITE}{'Enabled' if self.service_detection else 'Disabled'}")
        print(f"{Fore.YELLOW}Banner Grabbing: {Fore.WHITE}{'Enabled' if self.banner_grabbing else 'Disabled'}")
        print(f"{Fore.YELLOW}Vulnerability Scan: {Fore.WHITE}{'Enabled' if self.vuln_scan else 'Disabled'}")
        print(f"{Fore.CYAN}{'='*70}\n")
    
    def _tcp_scan(self):
        """Perform TCP connect scan"""
        if TQDM_AVAILABLE:
            pbar = tqdm(total=self.total_ports, desc="Scanning", unit="port")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_port = {
                executor.submit(self._tcp_scan_port, port): port 
                for port in self.ports
            }
            
            for future in as_completed(future_to_port):
                if self.cancelled:
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
                
                try:
                    result = future.result()
                    self._add_result(result)
                    if TQDM_AVAILABLE:
                        pbar.update(1)
                except Exception as e:
                    pass
        
        if TQDM_AVAILABLE:
            pbar.close()
    
    def _tcp_scan_port(self, port: int) -> Dict:
        """Scan a single port using TCP connect"""
        start = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        
        try:
            result = sock.connect_ex((self.target_ip, port))
            response_time = (time.time() - start) * 1000
            
            if result == 0:
                # Port is open
                service = Config.COMMON_SERVICES.get(port, 'Unknown')
                version = None
                banner = None
                
                # Banner grabbing
                if self.banner_grabbing and self.service_detector:
                    service, version, banner = self.service_detector.detect(self.target_ip, port)
                
                return {
                    'port': port,
                    'state': 'open',
                    'service': service,
                    'version': version,
                    'banner': banner,
                    'response_time': round(response_time, 2)
                }
            else:
                return {
                    'port': port,
                    'state': 'closed',
                    'service': None,
                    'version': None,
                    'banner': None,
                    'response_time': None
                }
        
        except socket.timeout:
            return {'port': port, 'state': 'filtered', 'service': None, 'version': None, 'banner': None, 'response_time': None}
        except Exception:
            return {'port': port, 'state': 'error', 'service': None, 'version': None, 'banner': None, 'response_time': None}
        finally:
            sock.close()
    
    def _udp_scan(self):
        """Perform UDP scan"""
        print(f"{Fore.YELLOW}Note: UDP scanning is less reliable and slower{Style.RESET_ALL}\n")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_port = {
                executor.submit(self._udp_scan_port, port): port 
                for port in self.ports
            }
            
            for future in as_completed(future_to_port):
                if self.cancelled:
                    break
                try:
                    result = future.result()
                    self._add_result(result)
                except:
                    pass
    
    def _udp_scan_port(self, port: int) -> Dict:
        """Scan a single UDP port"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        
        try:
            sock.sendto(b'', (self.target_ip, port))
            try:
                data, addr = sock.recvfrom(1024)
                state = 'open'
            except socket.timeout:
                state = 'open|filtered'
            
            return {
                'port': port,
                'state': state,
                'service': Config.COMMON_SERVICES.get(port, 'Unknown'),
                'version': None,
                'banner': None,
                'response_time': None
            }
        except:
            return {'port': port, 'state': 'closed', 'service': None, 'version': None, 'banner': None, 'response_time': None}
        finally:
            sock.close()
    
    def _syn_scan(self):
        """Perform SYN scan (requires scapy and privileges)"""
        if not SCAPY_AVAILABLE:
            raise ImportError("SYN scan requires scapy. Install with: pip install scapy")
        
        print(f"{Fore.YELLOW}Note: SYN scan requires administrator privileges{Style.RESET_ALL}\n")
        
        try:
            conf.verb = 0
            packets = IP(dst=self.target_ip)/TCP(dport=self.ports, flags='S')
            answered, unanswered = sr(packets, timeout=self.timeout, verbose=0)
            
            for sent, received in answered:
                port = sent[TCP].dport
                if received.haslayer(TCP):
                    if received[TCP].flags == 0x12:  # SYN-ACK
                        state = 'open'
                    elif received[TCP].flags == 0x14:  # RST-ACK
                        state = 'closed'
                    else:
                        state = 'filtered'
                else:
                    state = 'filtered'
                
                result = {
                    'port': port,
                    'state': state,
                    'service': Config.COMMON_SERVICES.get(port, 'Unknown') if state == 'open' else None,
                    'version': None,
                    'banner': None,
                    'response_time': None
                }
                self._add_result(result)
            
            for sent in unanswered:
                port = sent[TCP].dport
                self._add_result({'port': port, 'state': 'filtered', 'service': None, 'version': None, 'banner': None, 'response_time': None})
        
        except PermissionError:
            raise PermissionError("SYN scan requires administrator/root privileges")
    
    def _add_result(self, result: Dict):
        """Add a scan result and update statistics"""
        with self.lock:
            self.results.append(result)
            
            if result['state'] == 'open':
                self.open_ports.append(result['port'])
                
                # Print open port immediately
                service_info = f"{result['service']}" if result['service'] else "Unknown"
                version_info = f" ({result['version']})" if result.get('version') else ""
                print(f"{Fore.GREEN}[+] Port {result['port']}/tcp open - {service_info}{version_info}{Style.RESET_ALL}")
                
                # Vulnerability scanning
                if self.vuln_scan and self.vuln_scanner:
                    vulns = self.vuln_scanner.scan(result['port'], result['service'], result.get('banner', ''))
                    if vulns:
                        self.vulnerabilities.extend(vulns)
                        for vuln in vulns:
                            severity_color = {
                                'critical': Fore.RED,
                                'high': Fore.RED,
                                'medium': Fore.YELLOW,
                                'low': Fore.CYAN
                            }.get(vuln['severity'], Fore.WHITE)
                            print(f"{severity_color}    [!] {vuln['title']} ({vuln['severity'].upper()}){Style.RESET_ALL}")
            
            self.scanned_count += 1
            
            if self.progress_callback:
                progress = (self.scanned_count / self.total_ports) * 100
                self.progress_callback(self.scanned_count, self.total_ports, progress)
    
    def _compile_results(self) -> Dict:
        """Compile final scan results"""
        duration = (self.end_time - self.start_time).total_seconds()
        
        self.results.sort(key=lambda x: x['port'])
        self.open_ports.sort()
        
        summary = {
            'target': self.target,
            'target_ip': self.target_ip,
            'scan_type': self.scan_type,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat(),
            'duration': round(duration, 2),
            'total_ports': self.total_ports,
            'open_ports': len(self.open_ports),
            'results': self.results,
            'open_port_list': self.open_ports,
            'vulnerabilities': self.vulnerabilities
        }
        
        self._print_summary(summary)
        
        return summary
    
    def _print_summary(self, summary: Dict):
        """Print scan summary"""
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}Scan Summary")
        print(f"{Fore.CYAN}{'='*70}")
        print(f"{Fore.YELLOW}Duration: {Fore.WHITE}{summary['duration']:.2f} seconds")
        print(f"{Fore.YELLOW}Open Ports: {Fore.GREEN}{summary['open_ports']}")
        
        if summary['open_port_list']:
            print(f"{Fore.YELLOW}Port List: {Fore.WHITE}{', '.join(map(str, summary['open_port_list']))}")
        
        if summary['vulnerabilities']:
            print(f"{Fore.RED}Vulnerabilities Found: {len(summary['vulnerabilities'])}")
        
        print(f"{Fore.CYAN}{'='*70}\n")


# ============================================================================
# EXPORT FUNCTIONS
# ============================================================================

def export_json(results: Dict, filename: str):
    """Export results to JSON"""
    with open(filename, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"{Fore.GREEN}Results exported to {filename}{Style.RESET_ALL}")


def export_csv(results: Dict, filename: str):
    """Export results to CSV"""
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Port', 'State', 'Service', 'Version', 'Banner', 'Response Time (ms)'])
        
        for result in results['results']:
            if result['state'] == 'open':
                writer.writerow([
                    result['port'],
                    result['state'],
                    result.get('service', ''),
                    result.get('version', ''),
                    result.get('banner', ''),
                    result.get('response_time', '')
                ])
    
    print(f"{Fore.GREEN}Results exported to {filename}{Style.RESET_ALL}")


def export_html(results: Dict, filename: str):
    """Export results to HTML"""
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Port Scan Results - {results['target']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #1a1a1a; color: #fff; }}
        h1 {{ color: #00ff00; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
        th, td {{ border: 1px solid #444; padding: 12px; text-align: left; }}
        th {{ background-color: #333; color: #00ff00; }}
        tr:nth-child(even) {{ background-color: #2a2a2a; }}
        .open {{ color: #00ff00; }}
        .closed {{ color: #ff0000; }}
        .info {{ background: #2a2a2a; padding: 15px; border-radius: 5px; margin: 20px 0; }}
    </style>
</head>
<body>
    <h1>Port Scan Results</h1>
    <div class="info">
        <p><strong>Target:</strong> {results['target']} ({results['target_ip']})</p>
        <p><strong>Scan Type:</strong> {results['scan_type'].upper()}</p>
        <p><strong>Start Time:</strong> {results['start_time']}</p>
        <p><strong>Duration:</strong> {results['duration']} seconds</p>
        <p><strong>Open Ports:</strong> {results['open_ports']}</p>
    </div>
    
    <h2>Open Ports</h2>
    <table>
        <tr>
            <th>Port</th>
            <th>Service</th>
            <th>Version</th>
            <th>Banner</th>
            <th>Response Time</th>
        </tr>
"""
    
    for result in results['results']:
        if result['state'] == 'open':
            html += f"""
        <tr>
            <td class="open">{result['port']}</td>
            <td>{result.get('service', 'Unknown')}</td>
            <td>{result.get('version', 'N/A')}</td>
            <td>{result.get('banner', 'N/A')[:100]}</td>
            <td>{result.get('response_time', 'N/A')} ms</td>
        </tr>
"""
    
    html += """
    </table>
</body>
</html>
"""
    
    with open(filename, 'w') as f:
        f.write(html)
    
    print(f"{Fore.GREEN}Results exported to {filename}{Style.RESET_ALL}")


# ============================================================================
# WEB INTERFACE
# ============================================================================

# Try to import Flask for web interface
try:
    from flask import Flask, render_template_string, request, jsonify
    from flask_cors import CORS
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

# Global storage for active scans
active_scans = {}
scan_history = []
scan_counter = 0

def create_web_app():
    """Create Flask web application"""
    if not FLASK_AVAILABLE:
        print(f"{Fore.RED}Flask is not installed. Install with: pip install flask flask-cors{Style.RESET_ALL}")
        return None
    
    app = Flask(__name__)
    CORS(app)
    
    # HTML Template for the web interface
    HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Professional Port Scanner</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        .header {
            text-align: center;
            color: white;
            margin-bottom: 30px;
            animation: fadeIn 0.5s ease-in;
        }
        
        .header h1 {
            font-size: 3em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        
        .header p {
            font-size: 1.2em;
            opacity: 0.9;
        }
        
        .card {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            padding: 30px;
            margin-bottom: 20px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            backdrop-filter: blur(10px);
            animation: slideUp 0.5s ease-out;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #333;
        }
        
        .form-group input, .form-group select {
            width: 100%;
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 10px;
            font-size: 16px;
            transition: all 0.3s;
        }
        
        .form-group input:focus, .form-group select:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        
        .checkbox-group {
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
        }
        
        .checkbox-group label {
            display: flex;
            align-items: center;
            gap: 8px;
            cursor: pointer;
        }
        
        .checkbox-group input[type="checkbox"] {
            width: auto;
            cursor: pointer;
        }
        
        .btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px 40px;
            border: none;
            border-radius: 10px;
            font-size: 18px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(102, 126, 234, 0.6);
        }
        
        .btn:active {
            transform: translateY(0);
        }
        
        .btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
        }
        
        .progress-container {
            display: none;
            margin-top: 20px;
        }
        
        .progress-bar {
            width: 100%;
            height: 30px;
            background: #e0e0e0;
            border-radius: 15px;
            overflow: hidden;
            position: relative;
        }
        
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
            width: 0%;
            transition: width 0.3s;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: 600;
        }
        
        .results {
            display: none;
            margin-top: 20px;
        }
        
        .result-item {
            background: #f8f9fa;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 10px;
            border-left: 4px solid #28a745;
            animation: slideIn 0.3s ease-out;
        }
        
        .result-item.vuln {
            border-left-color: #dc3545;
        }
        
        .result-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }
        
        .port-number {
            font-size: 1.3em;
            font-weight: 700;
            color: #28a745;
        }
        
        .service-name {
            color: #666;
            font-weight: 500;
        }
        
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 600;
        }
        
        .badge-success {
            background: #d4edda;
            color: #155724;
        }
        
        .badge-danger {
            background: #f8d7da;
            color: #721c24;
        }
        
        .badge-warning {
            background: #fff3cd;
            color: #856404;
        }
        
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        
        .summary-item {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 15px;
            text-align: center;
        }
        
        .summary-item h3 {
            font-size: 2.5em;
            margin-bottom: 5px;
        }
        
        .summary-item p {
            opacity: 0.9;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        
        @keyframes slideUp {
            from {
                opacity: 0;
                transform: translateY(20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateX(-20px);
            }
            to {
                opacity: 1;
                transform: translateX(0);
            }
        }
        
        .status-message {
            padding: 15px;
            border-radius: 10px;
            margin-top: 15px;
            display: none;
        }
        
        .status-message.info {
            background: #d1ecf1;
            color: #0c5460;
        }
        
        .status-message.success {
            background: #d4edda;
            color: #155724;
        }
        
        .status-message.error {
            background: #f8d7da;
            color: #721c24;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Professional Port Scanner</h1>
            <p>Advanced network security scanning tool</p>
        </div>
        
        <div class="card">
            <h2 style="margin-bottom: 20px; color: #333;">Configure Scan</h2>
            
            <form id="scanForm">
                <div class="form-group">
                    <label for="target">Target Host</label>
                    <input type="text" id="target" name="target" placeholder="e.g., scanme.nmap.org or 192.168.1.1" required>
                </div>
                
                <div class="form-group">
                    <label for="profile">Scan Profile</label>
                    <select id="profile" name="profile">
                        <option value="quick">Quick Scan (Top 100 ports)</option>
                        <option value="normal" selected>Normal Scan (Ports 1-1024)</option>
                        <option value="deep">Deep Scan (All 65535 ports)</option>
                        <option value="custom">Custom Ports</option>
                    </select>
                </div>
                
                <div class="form-group" id="customPortsGroup" style="display: none;">
                    <label for="customPorts">Custom Ports</label>
                    <input type="text" id="customPorts" name="customPorts" placeholder="e.g., 80,443,8080 or 1-1000">
                </div>
                
                <div class="form-group">
                    <label>Advanced Options</label>
                    <div class="checkbox-group">
                        <label>
                            <input type="checkbox" name="banner" id="banner">
                            Banner Grabbing
                        </label>
                        <label>
                            <input type="checkbox" name="vuln" id="vuln">
                            Vulnerability Scan
                        </label>
                    </div>
                </div>
                
                <button type="submit" class="btn" id="scanBtn">Start Scan</button>
            </form>
            
            <div class="status-message" id="statusMessage"></div>
            
            <div class="progress-container" id="progressContainer">
                <h3 style="margin-bottom: 10px;">Scanning in progress...</h3>
                <div class="progress-bar">
                    <div class="progress-fill" id="progressFill">0%</div>
                </div>
                <p id="progressText" style="margin-top: 10px; color: #666;"></p>
            </div>
        </div>
        
        <div class="card results" id="resultsCard">
            <h2 style="margin-bottom: 20px; color: #333;">Scan Results</h2>
            
            <div class="summary" id="summary"></div>
            
            <h3 style="margin: 20px 0 15px 0; color: #333;">Open Ports</h3>
            <div id="resultsContainer"></div>
            
            <div style="margin-top: 20px;">
                <button class="btn" onclick="exportResults('json')">Export JSON</button>
                <button class="btn" onclick="exportResults('csv')" style="margin-left: 10px;">Export CSV</button>
                <button class="btn" onclick="exportResults('html')" style="margin-left: 10px;">Export HTML</button>
            </div>
        </div>
    </div>
    
    <script>
        let currentScanId = null;
        let currentResults = null;
        
        document.getElementById('profile').addEventListener('change', function() {
            const customGroup = document.getElementById('customPortsGroup');
            customGroup.style.display = this.value === 'custom' ? 'block' : 'none';
        });
        
        document.getElementById('scanForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const formData = new FormData(e.target);
            const data = {
                target: formData.get('target'),
                profile: formData.get('profile'),
                banner: formData.get('banner') === 'on',
                vuln: formData.get('vuln') === 'on'
            };
            
            if (data.profile === 'custom') {
                data.ports = formData.get('customPorts');
            }
            
            startScan(data);
        });
        
        async function startScan(data) {
            const btn = document.getElementById('scanBtn');
            const progressContainer = document.getElementById('progressContainer');
            const resultsCard = document.getElementById('resultsCard');
            const statusMessage = document.getElementById('statusMessage');
            
            btn.disabled = true;
            progressContainer.style.display = 'block';
            resultsCard.style.display = 'none';
            
            showStatus('Starting scan...', 'info');
            
            try {
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });
                
                const result = await response.json();
                
                if (result.success) {
                    currentScanId = result.scan_id;
                    showStatus('Scan started successfully!', 'success');
                    pollScanStatus();
                } else {
                    showStatus('Error: ' + result.error, 'error');
                    btn.disabled = false;
                    progressContainer.style.display = 'none';
                }
            } catch (error) {
                showStatus('Error: ' + error.message, 'error');
                btn.disabled = false;
                progressContainer.style.display = 'none';
            }
        }
        
        async function pollScanStatus() {
            const interval = setInterval(async () => {
                try {
                    const response = await fetch(`/api/scan/${currentScanId}`);
                    const data = await response.json();
                    
                    if (data.status === 'running') {
                        updateProgress(data.progress);
                    } else if (data.status === 'completed') {
                        clearInterval(interval);
                        displayResults(data.results);
                    } else if (data.status === 'error') {
                        clearInterval(interval);
                        showStatus('Scan failed: ' + data.error, 'error');
                        document.getElementById('scanBtn').disabled = false;
                        document.getElementById('progressContainer').style.display = 'none';
                    }
                } catch (error) {
                    clearInterval(interval);
                    showStatus('Error polling status: ' + error.message, 'error');
                }
            }, 1000);
        }
        
        function updateProgress(progress) {
            const fill = document.getElementById('progressFill');
            const text = document.getElementById('progressText');
            const percent = Math.round(progress);
            
            fill.style.width = percent + '%';
            fill.textContent = percent + '%';
            text.textContent = `Scanned ${percent}% of ports...`;
        }
        
        function displayResults(results) {
            currentResults = results;
            
            document.getElementById('scanBtn').disabled = false;
            document.getElementById('progressContainer').style.display = 'none';
            document.getElementById('resultsCard').style.display = 'block';
            
            // Summary
            const summary = document.getElementById('summary');
            summary.innerHTML = `
                <div class="summary-item">
                    <h3>${results.open_ports}</h3>
                    <p>Open Ports</p>
                </div>
                <div class="summary-item">
                    <h3>${results.duration}s</h3>
                    <p>Duration</p>
                </div>
                <div class="summary-item">
                    <h3>${results.total_ports}</h3>
                    <p>Total Scanned</p>
                </div>
                <div class="summary-item">
                    <h3>${results.vulnerabilities ? results.vulnerabilities.length : 0}</h3>
                    <p>Vulnerabilities</p>
                </div>
            `;
            
            // Results
            const container = document.getElementById('resultsContainer');
            container.innerHTML = '';
            
            if (results.open_port_list.length === 0) {
                container.innerHTML = '<p style="color: #666;">No open ports found.</p>';
                return;
            }
            
            results.results.forEach(result => {
                if (result.state === 'open') {
                    const div = document.createElement('div');
                    div.className = 'result-item';
                    
                    let content = `
                        <div class="result-header">
                            <div>
                                <span class="port-number">Port ${result.port}</span>
                                <span class="service-name"> - ${result.service || 'Unknown'}</span>
                            </div>
                            <span class="badge badge-success">OPEN</span>
                        </div>
                    `;
                    
                    if (result.version) {
                        content += `<p><strong>Version:</strong> ${result.version}</p>`;
                    }
                    
                    if (result.banner) {
                        content += `<p><strong>Banner:</strong> <code>${result.banner.substring(0, 100)}</code></p>`;
                    }
                    
                    if (result.response_time) {
                        content += `<p><strong>Response Time:</strong> ${result.response_time}ms</p>`;
                    }
                    
                    div.innerHTML = content;
                    container.appendChild(div);
                }
            });
            
            // Vulnerabilities
            if (results.vulnerabilities && results.vulnerabilities.length > 0) {
                const vulnHeader = document.createElement('h3');
                vulnHeader.textContent = 'Vulnerabilities Found';
                vulnHeader.style.marginTop = '20px';
                vulnHeader.style.color = '#dc3545';
                container.appendChild(vulnHeader);
                
                results.vulnerabilities.forEach(vuln => {
                    const div = document.createElement('div');
                    div.className = 'result-item vuln';
                    div.innerHTML = `
                        <div class="result-header">
                            <div>
                                <strong>${vuln.title}</strong>
                            </div>
                            <span class="badge badge-danger">${vuln.severity.toUpperCase()}</span>
                        </div>
                        <p><strong>Port:</strong> ${vuln.port} (${vuln.service})</p>
                        <p>${vuln.description}</p>
                    `;
                    container.appendChild(div);
                });
            }
            
            showStatus('Scan completed successfully!', 'success');
        }
        
        function showStatus(message, type) {
            const statusMessage = document.getElementById('statusMessage');
            statusMessage.textContent = message;
            statusMessage.className = 'status-message ' + type;
            statusMessage.style.display = 'block';
            
            setTimeout(() => {
                statusMessage.style.display = 'none';
            }, 5000);
        }
        
        async function exportResults(format) {
            if (!currentResults) return;
            
            try {
                const response = await fetch('/api/export', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        results: currentResults,
                        format: format
                    })
                });
                
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `scan_${currentResults.target}_${new Date().getTime()}.${format}`;
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                document.body.removeChild(a);
                
                showStatus(`Results exported as ${format.toUpperCase()}`, 'success');
            } catch (error) {
                showStatus('Export failed: ' + error.message, 'error');
            }
        }
    </script>
</body>
</html>
    """
    
    @app.route('/')
    def index():
        """Serve the main web interface"""
        return render_template_string(HTML_TEMPLATE)
    
    @app.route('/api/scan', methods=['POST'])
    def start_scan():
        """Start a new port scan"""
        global scan_counter
        
        try:
            data = request.json
            target = data.get('target')
            profile = data.get('profile', 'normal')
            banner = data.get('banner', False)
            vuln = data.get('vuln', False)
            
            # Determine ports
            if profile == 'custom':
                ports = parse_ports(data.get('ports', '1-1024'))
            else:
                profile_config = Config.SCAN_PROFILES.get(profile, Config.SCAN_PROFILES['normal'])
                ports = profile_config['ports']
            
            # Create scan ID
            scan_counter += 1
            scan_id = f"scan_{scan_counter}"
            
            # Initialize scan status
            active_scans[scan_id] = {
                'status': 'running',
                'progress': 0,
                'results': None,
                'error': None
            }
            
            # Start scan in background thread
            def run_scan():
                try:
                    def progress_callback(scanned, total, progress):
                        active_scans[scan_id]['progress'] = progress
                    
                    scanner = PortScanner(
                        target=target,
                        ports=ports,
                        service_detection=True,
                        banner_grabbing=banner,
                        vuln_scan=vuln,
                        progress_callback=progress_callback
                    )
                    
                    results = scanner.scan()
                    active_scans[scan_id]['status'] = 'completed'
                    active_scans[scan_id]['results'] = results
                    scan_history.append(results)
                    
                except Exception as e:
                    active_scans[scan_id]['status'] = 'error'
                    active_scans[scan_id]['error'] = str(e)
            
            thread = threading.Thread(target=run_scan)
            thread.daemon = True
            thread.start()
            
            return jsonify({'success': True, 'scan_id': scan_id})
        
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 400
    
    @app.route('/api/scan/<scan_id>', methods=['GET'])
    def get_scan_status(scan_id):
        """Get scan status"""
        if scan_id not in active_scans:
            return jsonify({'error': 'Scan not found'}), 404
        
        scan = active_scans[scan_id]
        return jsonify(scan)
    
    @app.route('/api/export', methods=['POST'])
    def export_scan():
        """Export scan results"""
        try:
            data = request.json
            results = data.get('results')
            format_type = data.get('format', 'json')
            
            if format_type == 'json':
                return jsonify(results)
            elif format_type == 'csv':
                # Generate CSV
                output = "Port,State,Service,Version,Banner,Response Time\n"
                for result in results['results']:
                    if result['state'] == 'open':
                        output += f"{result['port']},{result['state']},{result.get('service', '')},"
                        output += f"{result.get('version', '')},{result.get('banner', '')},"
                        output += f"{result.get('response_time', '')}\n"
                
                from flask import Response
                return Response(output, mimetype='text/csv')
            elif format_type == 'html':
                # Use existing export_html function
                import tempfile
                with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
                    export_html(results, f.name)
                    with open(f.name, 'r') as html_file:
                        html_content = html_file.read()
                    from flask import Response
                    return Response(html_content, mimetype='text/html')
        
        except Exception as e:
            return jsonify({'error': str(e)}), 400
    
    return app


def start_web_server(host='0.0.0.0', port=5000):
    """Start the web server"""
    app = create_web_app()
    if app:
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}Starting Web Interface")
        print(f"{Fore.CYAN}{'='*70}")
        print(f"{Fore.GREEN}Server running at: http://localhost:{port}")
        print(f"{Fore.YELLOW}Press Ctrl+C to stop the server")
        print(f"{Fore.CYAN}{'='*70}\n")
        
        app.run(host=host, port=port, debug=False)


# ============================================================================
# MAIN FUNCTION
# ============================================================================

def parse_ports(port_string: str) -> List[int]:
    """Parse port string into list of ports"""
    ports = []
    
    for part in port_string.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    
    return ports


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Professional Port Scanner Suite',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s scanme.nmap.org
  %(prog)s 192.168.1.1 -p 1-1000
  %(prog)s example.com -p 80,443,8080 --banner
  %(prog)s 10.0.0.1 --profile quick --vuln
  %(prog)s localhost -p 1-65535 --threads 100 --output results.json
        """
    )
    
    parser.add_argument('target', nargs='?', help='Target IP address or hostname')
    parser.add_argument('--web', action='store_true', help='Start web interface')
    parser.add_argument('-p', '--ports', default='1-1024', help='Ports to scan (e.g., 80,443 or 1-1000)')
    parser.add_argument('--profile', choices=['quick', 'normal', 'deep'], help='Use scan profile')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads (default: 50)')
    parser.add_argument('--timeout', type=float, default=0.5, help='Socket timeout in seconds (default: 0.5)')
    parser.add_argument('--scan-type', choices=['tcp', 'udp', 'syn'], default='tcp', help='Scan type (default: tcp)')
    parser.add_argument('--banner', action='store_true', help='Enable banner grabbing')
    parser.add_argument('--vuln', action='store_true', help='Enable vulnerability scanning')
    parser.add_argument('-o', '--output', help='Output file (supports .json, .csv, .html)')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    parser.add_argument('--port', type=int, default=5000, help='Web server port (default: 5000)')
    
    args = parser.parse_args()
    
    # Launch web interface if requested
    if args.web:
        start_web_server(port=args.port)
        return
    
    # Require target if not launching web interface
    if not args.target:
        parser.error('target is required unless --web is specified')
    
    # Disable colors if requested
    if args.no_color:
        global COLORS_AVAILABLE
        COLORS_AVAILABLE = False
    
    try:
        # Determine ports to scan
        if args.profile:
            profile = Config.SCAN_PROFILES[args.profile]
            ports = profile['ports']
            timeout = profile['timeout']
            threads = profile['threads']
        else:
            ports = parse_ports(args.ports)
            timeout = args.timeout
            threads = args.threads
        
        # Create scanner
        scanner = PortScanner(
            target=args.target,
            ports=ports,
            scan_type=args.scan_type,
            timeout=timeout,
            threads=threads,
            service_detection=True,
            banner_grabbing=args.banner,
            vuln_scan=args.vuln
        )
        
        # Run scan
        results = scanner.scan()
        
        # Export results
        if args.output:
            if args.output.endswith('.json'):
                export_json(results, args.output)
            elif args.output.endswith('.csv'):
                export_csv(results, args.output)
            elif args.output.endswith('.html'):
                export_html(results, args.output)
            else:
                print(f"{Fore.YELLOW}Unknown file format. Defaulting to JSON.{Style.RESET_ALL}")
                export_json(results, args.output + '.json')
    
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Scan cancelled by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
        sys.exit(1)


if __name__ == '__main__':
    # Check if running with arguments
    if len(sys.argv) > 1:
        main()
    else:
        # Interactive mode (original behavior)
        subprocess.call('cls', shell=True)
        
        print(f"{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}Professional Port Scanner Suite")
        print(f"{Fore.CYAN}{'='*70}\n")
        
        remoteServer = input(f"{Fore.YELLOW}Enter target host to scan: {Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}Select scan profile:")
        print(f"{Fore.WHITE}1. Quick Scan (Top 100 ports)")
        print(f"{Fore.WHITE}2. Normal Scan (Ports 1-1024)")
        print(f"{Fore.WHITE}3. Deep Scan (All 65535 ports)")
        print(f"{Fore.WHITE}4. Custom")
        
        choice = input(f"{Fore.YELLOW}Choice [1-4]: {Style.RESET_ALL}") or "2"
        
        if choice == "1":
            profile = Config.SCAN_PROFILES['quick']
            ports = profile['ports']
        elif choice == "3":
            profile = Config.SCAN_PROFILES['deep']
            ports = profile['ports']
        elif choice == "4":
            port_input = input(f"{Fore.YELLOW}Enter ports (e.g., 80,443 or 1-1000): {Style.RESET_ALL}")
            ports = parse_ports(port_input)
        else:
            profile = Config.SCAN_PROFILES['normal']
            ports = profile['ports']
        
        banner_grab = input(f"{Fore.YELLOW}Enable banner grabbing? [y/N]: {Style.RESET_ALL}").lower() == 'y'
        vuln_scan = input(f"{Fore.YELLOW}Enable vulnerability scanning? [y/N]: {Style.RESET_ALL}").lower() == 'y'
        
        try:
            scanner = PortScanner(
                target=remoteServer,
                ports=ports,
                service_detection=True,
                banner_grabbing=banner_grab,
                vuln_scan=vuln_scan
            )
            
            results = scanner.scan()
            
            # Ask about export
            export = input(f"\n{Fore.YELLOW}Export results? [y/N]: {Style.RESET_ALL}").lower()
            if export == 'y':
                format_choice = input(f"{Fore.YELLOW}Format (json/csv/html): {Style.RESET_ALL}").lower()
                filename = f"scan_{remoteServer}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{format_choice}"
                
                if format_choice == 'json':
                    export_json(results, filename)
                elif format_choice == 'csv':
                    export_csv(results, filename)
                elif format_choice == 'html':
                    export_html(results, filename)
        
        except Exception as e:
            print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
            sys.exit(1)