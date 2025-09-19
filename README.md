<div align="center">
  <img src="https://i.postimg.cc/XJ0Hq2fr/wallhaven-x6ry2v.jpg" alt="banner" style="max-width:100%; border-radius:12px;"/>
</div>

<h1 align="center">Kits</h1>

<div align="center">
  <strong>A list of kits for everyone.</strong><br>
  Now on <b><i>Linux</i></b>
</div>

---

> [!Important] 
> This repository is **educational-only**. It describes *concepts* and *historic categories* of kernel/userland malware so defenders can **recognize, study, and detect** them. It **does not** provide operational code, exploitation recipes, nor step‑by‑step instructions to build or deploy malicious software. Use this content only in legal, controlled environments (isolated VMs, CTF labs you own, or explicit instructor-approved training setups).

--- 

## 🔍 High-level kit categories (conceptual descriptions)

* <span style="color:#ffb86b">**Module-hiding / Stealth**</span>

  * Concept: techniques aimed at making a component invisible to standard OS listings.
  * Defensive focus: integrity checks, kernel module signing, and monitoring kernel symbol tables.

* <span style="color:#7bed9f">**Privilege escalation**</span>

  * Concept: granting or elevating privileges without proper authorization.
  * Defensive focus: auditing credential changes, enabling least-privilege, and using LSMs (AppArmor/SELinux).

* <span style="color:#70a1ff">**Syscall hooking / interception (historical)**</span>

  * Concept: intercepting kernel entry points to alter behavior.
  * Defensive focus: integrity verification, ftrace/eBPF monitoring, and kernel self-protection features.

* <span style="color:#ff6b81">**Persistence mechanisms**</span>

  * Concept: techniques intended to survive reboots or updates.
  * Defensive focus: secure boot, package integrity, and monitoring startup paths.

* <span style="color:#b39cff">**I/O / filesystem tampering**</span>

  * Concept: hiding or altering files/metadata to conceal activity.
  * Defensive focus: filesystem integrity tools, auditd rules, and read-only baselines.

---

## 🛡️ Defensive & educational alternatives (safe labs)

* **eBPF / bpftrace** — trace system activity without modifying kernel memory. Great for learning detection patterns.
* **ftrace / tracepoints** — collect syscall/driver behavior for offline analysis.
* **Auditd + auditctl** — log sensitive syscalls and file attribute changes.
* **fanotify / inotify** — build userland policers/monitors for file operations.
* **Isolated VMs & snapshots** — always test in throwaway environments.
* **CTF-style exercises** — learn detection and remediation (write detectors, not exploit code).

---

## 📚 Recommended study plan (beginner → advanced)

1. Linux fundamentals (processes, permissions, modules)
2. Userland monitoring: `inotify`, `auditd`, `strace`
3. Tracing: `ftrace`, `perf`, `bpftrace` (produce read-only observers)
4. Build detection tooling (userland) that correlates events, raise alerts
5. Responsible disclosure and red-team/blue-team exercises in approved labs

---


