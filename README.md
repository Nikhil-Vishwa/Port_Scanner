# 🔍 Professional Port Scanner Suite

A powerful, feature-rich port scanner built in Python with multi-threading, service detection, banner grabbing, and vulnerability scanning capabilities.

![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## ✨ Features

### Core Scanning
- **Multi-threaded scanning** - Scan thousands of ports in seconds
- **Multiple scan types** - TCP Connect, UDP, SYN (stealth) scans
- **Flexible port ranges** - Scan specific ports, ranges, or use predefined profiles
- **Service detection** - Automatically identify services running on open ports
- **Banner grabbing** - Capture service banners for version detection
- **Vulnerability scanning** - Basic vulnerability detection for common issues

### Scan Profiles
- **Quick Scan** - Top 100 most common ports (~2 seconds)
- **Normal Scan** - Well-known ports 1-1024 (~10 seconds)
- **Deep Scan** - All 65,535 ports (several minutes)
- **Custom Scan** - Define your own port ranges

### Output & Export
- **Colored terminal output** - Easy-to-read results with color coding
- **Progress bars** - Real-time scan progress with tqdm
- **Multiple export formats** - JSON, CSV, HTML reports
- **Detailed results** - Response times, service versions, banners

### User Experience
- **Interactive mode** - User-friendly prompts for beginners
- **CLI mode** - Advanced command-line interface for automation
- **Graceful degradation** - Works without optional dependencies

## 🚀 Quick Start

### Installation

1. **Clone or download** this repository
2. **Install dependencies** (optional but recommended):

```bash
pip install -r requirements.txt
```

**Note:** The scanner works without any dependencies! Optional packages enhance the experience:
- `colorama` - Colored output
- `tqdm` - Progress bars
- `scapy` - SYN scan support (requires admin privileges)

### Basic Usage

#### Interactive Mode (Easiest)
Simply run the script without arguments:

```bash
python portscanner.py
```

You'll be prompted to enter:
- Target hostname or IP
- Scan profile (Quick/Normal/Deep/Custom)
- Optional features (banner grabbing, vulnerability scan)
- Export preferences

#### Command-Line Mode (Advanced)

**Scan common ports:**
```bash
python portscanner.py scanme.nmap.org
```

**Scan specific ports:**
```bash
python portscanner.py 192.168.1.1 -p 80,443,8080
```

**Scan port range:**
```bash
python portscanner.py example.com -p 1-1000
```

**Quick scan with banner grabbing:**
```bash
python portscanner.py 10.0.0.1 --profile quick --banner
```

**Full scan with vulnerability detection:**
```bash
python portscanner.py localhost -p 1-65535 --vuln --threads 100
```

**Export results:**
```bash
python portscanner.py target.com -p 1-1000 -o results.json
python portscanner.py target.com -p 1-1000 -o results.csv
python portscanner.py target.com -p 1-1000 -o results.html
```

## 📖 Command-Line Options

```
usage: portscanner.py [-h] [-p PORTS] [--profile {quick,normal,deep}]
                      [-t THREADS] [--timeout TIMEOUT]
                      [--scan-type {tcp,udp,syn}] [--banner] [--vuln]
                      [-o OUTPUT] [--no-color]
                      target

positional arguments:
  target                Target IP address or hostname

optional arguments:
  -h, --help            Show help message
  -p, --ports PORTS     Ports to scan (e.g., 80,443 or 1-1000)
  --profile PROFILE     Use scan profile (quick/normal/deep)
  -t, --threads THREADS Number of threads (default: 50)
  --timeout TIMEOUT     Socket timeout in seconds (default: 0.5)
  --scan-type TYPE      Scan type: tcp, udp, syn (default: tcp)
  --banner              Enable banner grabbing
  --vuln                Enable vulnerability scanning
  -o, --output FILE     Output file (.json, .csv, .html)
  --no-color            Disable colored output
```

## 🎯 Usage Examples

### Example 1: Quick Security Check
Scan your local network device for common vulnerabilities:

```bash
python portscanner.py 192.168.1.1 --profile quick --vuln
```

### Example 2: Web Server Analysis
Check a web server with banner grabbing:

```bash
python portscanner.py example.com -p 80,443,8080,8443 --banner -o webserver.html
```

### Example 3: Comprehensive Network Audit
Deep scan with all features enabled:

```bash
python portscanner.py target.local --profile deep --banner --vuln -o audit.json
```

### Example 4: Fast Custom Scan
Scan database ports with high thread count:

```bash
python portscanner.py db.server.com -p 3306,5432,27017,6379 -t 100 --banner
```

## 🔒 Security & Legal Notice

**⚠️ IMPORTANT:**

- **Only scan systems you own or have explicit permission to scan**
- Unauthorized port scanning may be illegal in your jurisdiction
- Port scanning can trigger intrusion detection systems (IDS/IPS)
- Some networks may block or rate-limit scanning activity
- SYN scans require administrator/root privileges

**This tool is for:**
- ✅ Security auditing your own systems
- ✅ Network troubleshooting
- ✅ Educational purposes
- ✅ Authorized penetration testing

**Not for:**
- ❌ Unauthorized network reconnaissance
- ❌ Malicious activities
- ❌ Scanning systems without permission

## 🛠️ Advanced Features

### Service Detection
The scanner automatically identifies services running on open ports:

```
[+] Port 22/tcp open - SSH (OpenSSH 8.2)
[+] Port 80/tcp open - HTTP (Apache 2.4.41)
[+] Port 3306/tcp open - MySQL (5.7.33)
```

### Banner Grabbing
Capture detailed service information:

```bash
python portscanner.py target.com -p 1-1000 --banner
```

Example output:
```
[+] Port 21/tcp open - FTP
    Banner: 220 ProFTPD 1.3.5 Server ready.
```

### Vulnerability Scanning
Detect common security issues:

```bash
python portscanner.py target.com --profile quick --vuln
```

Detects:
- Anonymous FTP access
- Unencrypted protocols (Telnet)
- Exposed databases (MySQL, MongoDB, Redis)
- Outdated service versions
- Default configurations

### Export Formats

**JSON** - Machine-readable, perfect for automation:
```json
{
  "target": "example.com",
  "open_ports": 5,
  "results": [...]
}
```

**CSV** - Import into Excel/spreadsheets:
```csv
Port,State,Service,Version,Banner,Response Time
80,open,HTTP,Apache 2.4,,,12.5
```

**HTML** - Professional report with styling:
- Formatted tables
- Color-coded results
- Scan metadata
- Easy to share

## ⚙️ Technical Details

### Scan Types

**TCP Connect Scan** (Default)
- Most reliable and accurate
- Completes full TCP handshake
- Works without special privileges
- Detectable by target systems

**UDP Scan**
- Scans UDP ports
- Less reliable (no response = open or filtered)
- Slower than TCP scans
- Useful for DNS, DHCP, SNMP services

**SYN Scan** (Stealth)
- Doesn't complete TCP handshake
- Requires administrator/root privileges
- Requires `scapy` library
- Less detectable than TCP connect

### Performance

- **Multi-threaded** - Up to 200 concurrent threads
- **Optimized timeouts** - Configurable per scan type
- **Smart defaults** - Balanced speed vs accuracy
- **Progress tracking** - Real-time updates

**Typical scan times:**
- Quick scan (100 ports): ~2-5 seconds
- Normal scan (1024 ports): ~10-20 seconds
- Deep scan (65535 ports): ~5-15 minutes (depends on threads)

## 🐛 Troubleshooting

**"Cannot resolve hostname"**
- Check your internet connection
- Verify the hostname is correct
- Try using an IP address instead

**"Permission denied" (SYN scan)**
- SYN scans require administrator privileges
- Run as admin: `sudo python portscanner.py ...` (Linux/Mac)
- Run PowerShell as Administrator (Windows)

**Slow scanning**
- Increase thread count: `-t 100`
- Reduce timeout: `--timeout 0.3`
- Use quick profile: `--profile quick`

**No colored output**
- Install colorama: `pip install colorama`
- Or disable colors: `--no-color`

## 📝 Requirements

- **Python 3.7+** (required)
- **colorama** (optional) - Colored output
- **tqdm** (optional) - Progress bars
- **scapy** (optional) - SYN scan support

## 🤝 Contributing

Contributions are welcome! Feel free to:
- Report bugs
- Suggest features
- Submit pull requests
- Improve documentation

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Inspired by nmap and other network scanning tools
- Built for educational and security auditing purposes
- Thanks to the Python community for excellent libraries

## 📞 Support

If you encounter issues or have questions:
1. Check the troubleshooting section
2. Review the examples
3. Run with `-h` for help
4. Check that you have the required Python version

---

**Remember:** Always scan responsibly and ethically! 🛡️
