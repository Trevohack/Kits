
# Hades - Blue Team Defensive Rootkit

A kernel-level defensive module designed for blue team operations to protect sensitive files and network services from reconnaissance attacks. Hades operates at ring 0 to provide robust protection against sophisticated attackers attempting to enumerate system resources.

## Features

### 🛡️ File & Directory Protection
- **Multi-prefix hiding**: Conceals files and directories starting with configurable prefixes
- **Pattern-based detection**: Hides files containing sensitive extensions
- **Dual syscall hooking**: Hooks both `getdents` and `getdents64` for complete coverage
- **Real-time filtering**: Files are hidden from all directory enumeration tools

### 🔒 Network Service Protection  
- **Connection stealth**: Hides network connections from enumeration tools
- **Multi-protocol support**: Protects TCP and UDP on both IPv4 and IPv6
- **Packet interception**: Drops packets targeting protected ports
- **Traffic analysis prevention**: Blocks network reconnaissance attempts

## Protected Assets

### File Prefixes (Default Configuration)
```
source-code*    - Source code repositories and development files
data*          - Data directories and databases  
classified*    - Classified documents and sensitive information
internal*      - Internal documentation and procedures
backup*        - Backup files and archives
forensic*      - Digital forensic evidence and analysis
incident*      - Incident response files and logs
```

### File Patterns
```
*.classified   - Files with classified extension
*.secret      - Secret documents
*.blueteam    - Blue team operational files  
*_defense     - Defense-related files
```

### Network Protection
- **Protected Port**: 8443 (configurable)
- **Protocols**: TCP/UDP over IPv4/IPv6
- **Coverage**: netstat, ss, lsof, tcpdump, wireshark

## Technical Implementation

### Kernel Hooks
```c
Syscall Hooks:
├── __x64_sys_getdents64  → File/directory enumeration (64-bit)
├── __x64_sys_getdents    → File/directory enumeration (32-bit)
└── Network Hooks:
    ├── tcp4_seq_show     → TCP IPv4 connection listing
    ├── tcp6_seq_show     → TCP IPv6 connection listing  
    ├── udp4_seq_show     → UDP IPv4 connection listing
    ├── udp6_seq_show     → UDP IPv6 connection listing
    └── tpacket_rcv       → Packet capture interception
```

### Hook Mechanism
- **Function**: Uses ftrace-based hooking for stealth and stability
- **Method**: Intercepts kernel function calls before execution
- **Filtering**: Processes and modifies results before returning to userspace
- **Performance**: Minimal overhead with efficient filtering algorithms

## Prerequisites

### System Requirements
- Linux kernel 4.15+ (tested on 4.15.0-91-generic)
- x86_64 architecture
- Root privileges for module loading
- Kernel headers for compilation

### Development Tools
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install build-essential linux-headers-$(uname -r)

# CentOS/RHEL/Fedora  
sudo yum groupinstall "Development Tools"
sudo yum install kernel-devel kernel-headers
```

### Required Files
```
hades.c           - Main module source code
ftrace_helper.h   - Ftrace hooking framework
Makefile          - Build configuration
```

## Installation & Usage

### Compilation
```bash
# Clean previous builds
make clean

# Compile the module
make

# Verify compilation
ls -la *.ko
```

### Loading the Module
```bash
# Load Hades module
sudo insmod hades.ko

# Verify module is loaded
lsmod | grep hades

# Check kernel logs
dmesg | grep -i hades
```

### Monitoring Operations
```bash
# View real-time kernel messages
sudo dmesg -w | grep -i hades

# Check system status
sudo journalctl -f | grep -i hades

# Monitor module status
watch -n 1 'lsmod | grep hades'
```

### Unloading the Module
```bash
# Safely remove module
sudo rmmod hades

# Verify removal
lsmod | grep hades

# Clean build artifacts
make clean
```

## Testing & Validation

### File Hiding Tests
```bash
# Create test files with protected prefixes
sudo touch /tmp/source-code-test.txt
sudo touch /tmp/data_analysis.log  
sudo touch /tmp/classified_document.pdf
sudo touch /tmp/normal_file.txt

# Test directory listing (protected files should be hidden)
ls -la /tmp/
find /tmp -name "*source*"    # Should return nothing
locate source-code            # Should not find protected files
```

### Network Hiding Tests  
```bash
# Start service on protected port
sudo nc -l 8443 &
sudo python3 -m http.server 8443 &

# Test network enumeration (should NOT show port 8443)
netstat -tulpn | grep 8443
ss -tulpn | grep 8443
lsof -i :8443
nmap -p 8443 localhost

# Test packet capture (should not see traffic)
sudo tcpdump -i any port 8443
```

### Advanced Testing
```bash
# Test with various tools
find / -name "*classified*" 2>/dev/null
locate -i forensic
grep -r "internal" /tmp/ 2>/dev/null

# Network reconnaissance simulation
nmap -sS -O -p 1-65535 localhost
masscan -p1-65535 127.0.0.1 --rate 1000
```

## Configuration & Customization

### Modifying Protected Prefixes
Edit the `file_prefixes` array in `hades.c`:
```c
static char *file_prefixes[MAX_PREFIXES] = {
    "source-code",
    "data", 
    "classified",
    "your-custom-prefix",    // Add custom prefixes
    "project-secret",        // Multiple prefixes supported
    NULL                     // Keep sentinel value
};
```

### Changing Protected Port
Modify the port definition:
```c
#define PROTECTED_PORT 9999  // Change to your desired port
```

### Adding File Patterns
Extend the `should_hide_file()` function:
```c
// Add custom patterns
if (strstr(name, ".confidential") || 
    strstr(name, "_hidden") ||
    strstr(name, "your-pattern")) {
    return 1;
}
```

### Multiple Port Protection
Implement array-based port checking:
```c
static int protected_ports[] = {8443, 9090, 31337, 0};

static int is_protected_port(int port) {
    int i;
    for (i = 0; protected_ports[i] != 0; i++) {
        if (protected_ports[i] == port) return 1;
    }
    return 0;
}
```

## Operational Security

### Deployment Best Practices
- **Pre-deployment testing**: Test thoroughly in isolated environments
- **Backup procedures**: Ensure system recovery methods are available
- **Monitoring setup**: Implement logging and alerting for module status
- **Documentation**: Maintain detailed deployment and configuration records

### Detection Evasion
- **Minimal logging**: Debug messages are commented out by default
- **Efficient processing**: Minimal performance impact to avoid suspicion
- **Selective hiding**: Only hides specifically configured assets
- **Stealth operation**: No obvious system modifications or artifacts

### Incident Response Integration
```bash
# Emergency module removal
echo 'sudo rmmod hades' > /tmp/emergency_remove.sh
chmod +x /tmp/emergency_remove.sh

# Status checking script
#!/bin/bash
if lsmod | grep -q hades; then
    echo "Hades module: ACTIVE"
else  
    echo "Hades module: INACTIVE"
fi
```

## Security Considerations

### Legitimate Use Cases
- **Incident response**: Protecting evidence and analysis tools
- **Digital forensics**: Concealing investigation activities
- **Red team exercises**: Simulating advanced persistent threats
- **Security research**: Testing detection capabilities
- **Sensitive operations**: Protecting classified information systems

### Limitations & Bypass Methods
- **Direct syscalls**: Advanced attackers may use direct system calls
- **Memory forensics**: In-memory analysis can detect hooks
- **Kernel debugging**: Kernel debuggers can identify modifications  
- **Static analysis**: Offline disk analysis bypasses runtime hiding
- **Root detection**: Rootkit scanners may detect ftrace modifications

### Countermeasures Against Bypasses
- **Kernel module signing**: Use signed modules in production
- **KASLR**: Enable Kernel Address Space Layout Randomization
- **SMEP/SMAP**: Utilize hardware security features
- **Control Flow Integrity**: Enable CFI if available
- **Regular updates**: Keep module updated for new kernel versions

## Troubleshooting

### Common Issues

#### Module Won't Load
```bash
# Check kernel version compatibility
uname -r
cat /proc/version

# Verify kernel headers
ls -la /lib/modules/$(uname -r)/build

# Check compilation errors
make clean && make 2>&1 | tee compile.log
```

#### Files Still Visible  
```bash
# Verify module loaded correctly
lsmod | grep hades
dmesg | grep -i error

# Check file naming matches prefixes exactly
ls -la /tmp/source-code*  # Should be hidden
ls -la /tmp/Source-Code*  # Different case - visible
```

#### Network Connections Showing
```bash
# Confirm service running on correct port
sudo lsof -i :8443
sudo ss -tulpn | grep 8443

# Test different enumeration tools
netstat -an | grep 8443
nmap -p 8443 localhost
```

#### System Instability
```bash
# Safe module removal
sudo rmmod hades

# Check system logs
sudo journalctl -n 50
dmesg | tail -20

# System recovery
sudo reboot  # If needed
```
