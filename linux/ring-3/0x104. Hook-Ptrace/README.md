
# Ptrace Hook - Anti-Debug Library

A userland ptrace interception library designed for blue team defensive operations to prevent attackers from using ptrace to analyze, debug, or inject code into protected processes.

## Overview

This library uses `LD_PRELOAD` to intercept ptrace system calls and block malicious debugging attempts while maintaining observability for security monitoring.

## Features

- **Selective Blocking**: Blocks dangerous ptrace operations while allowing legitimate debugging scenarios
- **Enhanced Logging**: Logs attempts with process information, timestamps, and request details
- **Centralized Monitoring**: Sends alerts to both stderr and syslog for SIEM integration
- **Minimal Performance Impact**: Lightweight interception with efficient logging

## Compilation

```bash
gcc -shared -fPIC -o libptrace_block.so ptrace_block.c -ldl
```

## Usage

### Single Process Protection
```bash
LD_PRELOAD=./libptrace_block.so ./your_protected_binary
```

### System-wide Protection (Use with Caution)
```bash
export LD_PRELOAD=/path/to/libptrace_block.so
```

### Service Integration
Add to systemd service file:
```ini
[Service]
Environment=LD_PRELOAD=/path/to/libptrace_block.so
ExecStart=/path/to/your/service
```

## Blocked Operations

The library blocks the following ptrace requests commonly used by attackers:

- `PTRACE_ATTACH` - Attaching to running processes
- `PTRACE_SEIZE` - Modern attach method
- `PTRACE_PEEKTEXT/DATA` - Reading process memory
- `PTRACE_POKETEXT/DATA` - Writing process memory
- `PTRACE_GETREGS/SETREGS` - Register manipulation
- `PTRACE_SYSCALL` - System call tracing
- `PTRACE_SINGLESTEP` - Single-step execution

## Allowed Operations

- `PTRACE_TRACEME` - Allows legitimate self-debugging scenarios

## Log Output

### Console Output
```
[2024-03-15 14:30:45] PTRACE BLOCKED: PID=1234, Process=malware, Request=1, Target=5678
```

### Syslog Output
```
Mar 15 14:30:45 hostname ptrace_monitor[1234]: Blocked ptrace attempt: PID=1234, Process=malware, Request=1, Target=5678
```

## Monitoring Integration

### rsyslog Configuration
Add to `/etc/rsyslog.conf`:
```
# Ptrace monitoring
:programname, isequal, "ptrace_monitor" /var/log/ptrace_blocks.log
& stop
```

### Log Analysis
Monitor for patterns indicating:
- Multiple rapid ptrace attempts (process scanning)
- Unknown processes attempting debugging
- Suspicious process names or paths

## Limitations

- **LD_PRELOAD Bypass**: Attackers can unset LD_PRELOAD or use static binaries
- **Kernel-level Attacks**: Direct system calls bypass userland hooks
- **Root Privileges**: Root users can potentially bypass these protections

## Complementary Defenses

Consider implementing alongside:
- **seccomp-bpf filters** for kernel-level ptrace blocking
- **YAMA ptrace_scope** settings (`/proc/sys/kernel/yama/ptrace_scope`)
- **Process monitoring** for suspicious debugging activity
- **File integrity monitoring** on critical binaries

## Customization

Modify the `ptrace()` function to:
- Allow specific legitimate debugging tools by process name
- Implement rate limiting for repeated attempts
- Add custom alerting mechanisms
- Integrate with existing security frameworks

## Security Considerations

- Deploy in test environment first
- May interfere with legitimate debugging tools
- Consider performance impact in high-throughput applications
- Regularly review logs for false positives
- Keep library updated as attack techniques evolve

## Testing

Test with common debugging tools to ensure proper functionality:
```bash
# Should be blocked
gdb -p <pid>
strace -p <pid>

# Should work (if PTRACE_TRACEME is allowed)
gdb ./your_binary
strace ./your_binary
```
