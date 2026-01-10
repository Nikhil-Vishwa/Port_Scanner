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
    
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-p', '--ports', default='1-1024', help='Ports to scan (e.g., 80,443 or 1-1000)')
    parser.add_argument('--profile', choices=['quick', 'normal', 'deep'], help='Use scan profile')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads (default: 50)')
    parser.add_argument('--timeout', type=float, default=0.5, help='Socket timeout in seconds (default: 0.5)')
    parser.add_argument('--scan-type', choices=['tcp', 'udp', 'syn'], default='tcp', help='Scan type (default: tcp)')
    parser.add_argument('--banner', action='store_true', help='Enable banner grabbing')
    parser.add_argument('--vuln', action='store_true', help='Enable vulnerability scanning')
    parser.add_argument('-o', '--output', help='Output file (supports .json, .csv, .html)')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    
    args = parser.parse_args()
    
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