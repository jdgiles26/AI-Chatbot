# Mac Mini M2 Security Assistant - User Guide

## Overview

The Mac Mini M2 Security Assistant is a comprehensive security monitoring and analysis tool specifically optimized for macOS on Apple Silicon (M1/M2) chips. It provides real-time file system scanning, security risk assessment, and detailed reporting capabilities.

## Features

### Core Capabilities
- **File System Scanning**: Deep scanning of directories with permission analysis
- **Security Risk Assessment**: Identifies potential vulnerabilities and security issues
- **Real-time Monitoring**: Continuous monitoring of file system changes
- **Comprehensive Reporting**: Generates detailed reports in JSON, HTML, and PDF formats
- **M2 Optimization**: Optimized for Apple Silicon architecture

### Security Checks
The assistant performs the following security checks:

1. **Permission Analysis**
   - Identifies overly permissive files (777, 666, etc.)
   - Detects world-writable files and directories
   - Flags SUID/SGID executables

2. **File Type Analysis**
   - Detects hidden executable files
   - Identifies suspicious file extensions
   - Analyzes sensitive files (keys, certificates, etc.)

3. **Ownership Analysis**
   - Checks for root-owned executables
   - Verifies file ownership consistency

4. **Change Monitoring**
   - Tracks file creation, modification, and deletion
   - Alerts on suspicious changes

## Installation

### Prerequisites
- macOS 10.15 or later
- Python 3.8 or higher
- Terminal access

### Quick Install
```bash
cd AI-Chatbot
chmod +x setup_assistant.sh
./setup_assistant.sh
```

### Manual Install
```bash
cd AI-Chatbot
pip3 install -r assistant/requirements.txt
chmod +x assistant/cli.py
```

## Usage

### Basic Commands

#### 1. Scan a Directory
```bash
python3 assistant/cli.py scan --path /Users/username
```

Options:
- `--path`: Path to scan (default: /)
- `--recursive`: Scan recursively (enabled by default)
- `--follow-symlinks`: Follow symbolic links
- `--output`: Save report to file
- `--format`: Report format (json, html, pdf)

#### 2. Generate Reports
```bash
# JSON report
python3 assistant/cli.py scan --path /Users --output security_report.json --format json

# HTML report
python3 assistant/cli.py scan --path /Applications --output security_report.html --format html
```

#### 3. Continuous Monitoring
```bash
python3 assistant/cli.py monitor --path /Users/username --interval 300
```

Options:
- `--path`: Path to monitor
- `--interval`: Check interval in seconds (default: 300)

Press Ctrl+C to stop monitoring.

### Advanced Usage

#### Scan Specific Directories
```bash
# Scan user home directory
python3 assistant/cli.py scan --path /Users/username --output ~/Desktop/scan_report.html --format html

# Scan applications
python3 assistant/cli.py scan --path /Applications --recursive

# Scan system directories (requires elevated permissions)
sudo python3 assistant/cli.py scan --path /System --output system_scan.json
```

#### Monitor Critical Directories
```bash
# Monitor Downloads folder
python3 assistant/cli.py monitor --path /Users/username/Downloads --interval 60

# Monitor Applications
python3 assistant/cli.py monitor --path /Applications --interval 600
```

## Understanding Reports

### Report Sections

#### 1. Scan Summary
Provides overview of:
- Total files and directories scanned
- Total size of scanned data
- Scan duration
- Platform information

#### 2. Security Issues
Categorized by severity:
- **Critical**: Immediate attention required (e.g., world-writable system files)
- **High**: Serious security concerns (e.g., hidden executables, dangerous permissions)
- **Medium**: Potential risks (e.g., suspicious file types)
- **Low**: Minor issues or informational findings

#### 3. Detailed Findings
Each finding includes:
- Issue type and severity
- File/directory path
- Description of the issue
- Mitigation steps
- References to security documentation

#### 4. Recommendations
Actionable security recommendations based on findings

### Sample Report Interpretation

**Critical Issue Example:**
```
Type: world_writable_directory
Severity: Critical
Path: /Users/Shared/sensitive_data
Description: Directory is world-writable - severe security risk
Mitigation: chmod o-w '/Users/Shared/sensitive_data'
```

**Action**: Immediately remove world-write permission to prevent unauthorized modifications.

**High Issue Example:**
```
Type: hidden_executable
Severity: High
Path: /Users/username/.config/.hidden_script
Description: Hidden executable file detected - potential security risk
Mitigation: Review file purpose. If unknown or unnecessary, remove it.
```

**Action**: Investigate the file, verify its purpose, and remove if suspicious.

## Best Practices

### Regular Scanning
1. **Daily Monitoring**: Monitor critical directories (Downloads, Applications)
2. **Weekly Scans**: Full system scans of user directories
3. **Monthly Audits**: Comprehensive security audits with reports

### Security Hardening
Based on assistant findings:

1. **Fix Permissions**
   ```bash
   # Fix overly permissive files
   chmod 644 filename
   
   # Fix overly permissive directories
   chmod 755 dirname
   ```

2. **Remove World-Writable Permissions**
   ```bash
   chmod o-w filename
   ```

3. **Review Hidden Files**
   ```bash
   # List all hidden files in home directory
   ls -la ~/ | grep "^\."
   ```

4. **Remove Suspicious Files**
   ```bash
   # After verification, remove suspicious files
   rm /path/to/suspicious/file
   ```

### Integration with System Tools

#### Combine with macOS Security Features
```bash
# Enable FileVault (if not already enabled)
# System Preferences > Security & Privacy > FileVault

# Check system integrity
csrutil status

# Verify app signatures
codesign -v /Applications/AppName.app
```

#### Automated Scanning with Cron
```bash
# Add to crontab for weekly scans
crontab -e

# Add this line for weekly Sunday scans at 2 AM
# Note: The percent signs must be escaped with backslash in crontab
0 2 * * 0 /usr/bin/python3 /path/to/AI-Chatbot/assistant/cli.py scan --path /Users --output /path/to/reports/weekly_$(date +\%Y\%m\%d).json
```

## Troubleshooting

### Common Issues

#### Permission Denied
**Issue**: Cannot scan certain directories
**Solution**: Run with elevated permissions
```bash
sudo python3 assistant/cli.py scan --path /System
```

#### Too Many Files
**Issue**: Scan takes too long or uses too much memory
**Solution**: 
1. Scan smaller directory trees
2. Add exclusions in `scanner.py`
3. Use `--no-recursive` flag (future feature)

#### False Positives
**Issue**: Legitimate files flagged as suspicious
**Solution**: Review findings carefully. The tool errs on the side of caution.

## Examples

### Example 1: Quick Security Check
```bash
# Quick scan of user directory
python3 assistant/cli.py scan --path /Users/$(whoami) --output ~/Desktop/security_check.html --format html

# Open the report
open ~/Desktop/security_check.html
```

### Example 2: Monitor Downloads Folder
```bash
# Start monitoring Downloads
python3 assistant/cli.py monitor --path ~/Downloads --interval 30

# Output will show file changes in real-time:
# [2025-12-16 10:30:15] file_created: /Users/username/Downloads/app.dmg
# [!] ALERT: Potentially suspicious file detected
```

### Example 3: Comprehensive System Audit
```bash
# Create audit directory
mkdir -p ~/SecurityAudits

# Scan and save reports
python3 assistant/cli.py scan --path /Users --output ~/SecurityAudits/users_audit.json
python3 assistant/cli.py scan --path /Applications --output ~/SecurityAudits/apps_audit.json

# Generate HTML versions
python3 assistant/cli.py scan --path /Users --output ~/SecurityAudits/users_audit.html --format html
```

## Support and Contributing

### Getting Help
- Check this documentation
- Review the README.md
- Open an issue on GitHub

### Contributing
Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## Security Considerations

### Privacy
- The assistant only scans local file systems
- No data is transmitted externally
- Reports are stored locally only

### Permissions
- Run with minimum required permissions
- Only use `sudo` when scanning system directories
- Review all findings before taking action

### Limitations
- Cannot detect all malware or vulnerabilities
- Should be used as part of comprehensive security strategy
- Regular updates to security patterns recommended

## License

This tool is part of the AI-Chatbot project and is licensed under the MIT License.
