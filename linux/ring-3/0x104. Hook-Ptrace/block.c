#define _GNU_SOURCE 
#include <stdio.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <string.h>


typedef long (*orig_ptrace_func_t)(enum __ptrace_request request, ...);
static orig_ptrace_func_t orig_ptrace = NULL;

static void init_ptrace(void) {
    if (!orig_ptrace) {
        orig_ptrace = (orig_ptrace_func_t)dlsym(RTLD_NEXT, "ptrace");
        if (!orig_ptrace) {
            fprintf(stderr, "Failed to load original ptrace: %s\n", dlerror());
        }
    }
}

static void log_ptrace_attempt(enum __ptrace_request request, pid_t pid) {
    time_t now;
    char time_str[64];
    char proc_name[256] = "unknown";
    FILE *cmdline_file;
    char cmdline_path[64];
    
    time(&now);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/comm", getpid());
    cmdline_file = fopen(cmdline_path, "r");
    if (cmdline_file) {
        if (fgets(proc_name, sizeof(proc_name), cmdline_file)) {
            proc_name[strcspn(proc_name, "\n")] = 0;
        }
        fclose(cmdline_file);
    }
  
    fprintf(stderr, "[%s] PTRACE BLOCKED: PID=%d, Process=%s, Request=%d, Target=%d\n", 
            time_str, getpid(), proc_name, request, pid);
    
    openlog("ptrace_monitor", LOG_PID | LOG_CONS, LOG_DAEMON);
    syslog(LOG_WARNING, "Blocked ptrace attempt: PID=%d, Process=%s, Request=%d, Target=%d", 
           getpid(), proc_name, request, pid);
    closelog();
}

long ptrace(enum __ptrace_request request, ...) {
    va_list args;
    pid_t pid = 0;
    void *addr = NULL;
    void *data = NULL;
    
    va_start(args, request);
    pid = va_arg(args, pid_t);
    if (request != PTRACE_TRACEME) {
        addr = va_arg(args, void*);
        data = va_arg(args, void*);
    }
    va_end(args);
    init_ptrace();
    log_ptrace_attempt(request, pid);
    
    switch (request) {
        case PTRACE_TRACEME:
            if (orig_ptrace) {
                return orig_ptrace(request, pid, addr, data);
            }
            break;
            
        case PTRACE_ATTACH:
        case PTRACE_SEIZE:
        case PTRACE_PEEKTEXT:
        case PTRACE_PEEKDATA:
        case PTRACE_PEEKUSER:
        case PTRACE_POKETEXT:
        case PTRACE_POKEDATA:
        case PTRACE_POKEUSER:
        case PTRACE_GETREGS:
        case PTRACE_SETREGS:
        case PTRACE_GETFPREGS:
        case PTRACE_SETFPREGS:
        case PTRACE_SYSCALL:
        case PTRACE_SINGLESTEP:
        case PTRACE_DETACH:
        default:
            errno = EPERM;
            return -1;
    }
    
    errno = EPERM;
    return -1;
}

__attribute__((constructor))
static void ptrace_init(void) {
    init_ptrace();
    fprintf(stderr, "Hacked ptrace PID %d\n", getpid());
}
