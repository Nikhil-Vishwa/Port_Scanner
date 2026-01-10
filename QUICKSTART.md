# 🚀 Quick Start Guide

## No Installation Needed!

The port scanner works **without any dependencies**. Just run it with Python!

## Basic Commands

### 1. Interactive Mode (Easiest)
```bash
python portscanner.py
```
Follow the prompts to configure your scan.

### 2. Quick Scan
```bash
python portscanner.py scanme.nmap.org --profile quick
```

### 3. Scan Specific Ports
```bash
python portscanner.py localhost -p 80,443,8080
```

### 4. Scan with Banner Grabbing
```bash
python portscanner.py scanme.nmap.org -p 1-1000 --banner
```

### 5. Vulnerability Scan
```bash
python portscanner.py target.com --profile quick --vuln
```

### 6. Export Results
```bash
python portscanner.py target.com -p 1-1000 -o results.json
python portscanner.py target.com -p 1-1000 -o results.csv
python portscanner.py target.com -p 1-1000 -o results.html
```

### 7. 🌐 Launch Web Interface (NEW!)
```bash
python portscanner.py --web
```
Then open your browser to: **http://localhost:5000**

## Optional: Install Dependencies for Enhanced Features

If you want colored output, progress bars, and the web interface:

```bash
pip install colorama tqdm flask flask-cors
```

Or install all at once:
```bash
pip install -r requirements.txt
```

## Troubleshooting

### PowerShell Execution Policy Error?
You don't need a virtual environment! Just run the commands directly:
```bash
python portscanner.py --help
```

### "Python not found"?
Make sure Python 3.7+ is installed and in your PATH.

### Slow scanning?
Increase threads:
```bash
python portscanner.py target.com -p 1-1000 -t 100
```

## Legal Notice ⚠️

**Only scan systems you own or have permission to scan!**

Unauthorized port scanning may be illegal in your jurisdiction.

## Need Help?

Run with `--help` to see all options:
```bash
python portscanner.py --help
```

Check the full README.md for comprehensive documentation.

---

**Enjoy your professional port scanner!** 🔍
