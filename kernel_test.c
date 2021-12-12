#include "netlink_kernel.c"
#include <linux/file.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include <asm/types.h>

MODULE_LICENSE("GPL");
// 定义了一种函数指针的别名为sys_call_ptr_t
// 参数和返回值都是void
typedef void (*sys_call_ptr_t)(void);
// 定义了一种函数指针的别名为old_syscal_t
// 参数为struct pt_regs*
typedef asmlinkage ssize_t (*old_syscall_t)(struct pt_regs* regs);
// pt_regs保存了用户态CPU寄存器的核心栈内容

// 用于保存原系统调用入口的地址
old_syscall_t old_read = NULL;
old_syscall_t old_write = NULL;
old_syscall_t old_execve = NULL;
old_syscall_t old_rename = NULL;
old_syscall_t old_unlink = NULL;
old_syscall_t old_unlinkat = NULL;
old_syscall_t old_getdents64 = NULL;
old_syscall_t old_openat = NULL;

// 系统调用入口地址表的地址
sys_call_ptr_t* sys_call_table = NULL;
pte_t* pte = NULL;
unsigned int level = 0;


/**
 * @brief 获得系统调用入口地址表
 *
 * @return sys_call_ptr_t*
 */
static sys_call_ptr_t* get_sys_call_table(void) {
    sys_call_ptr_t* _sys_call_table = NULL;

    _sys_call_table = (sys_call_ptr_t*)kallsyms_lookup_name("sys_call_table");

    return _sys_call_table;
}



asmlinkage ssize_t hooked_rename(struct pt_regs* regs) {
    unsigned long ino;
    uid_t uid;
    ssize_t ret = -1;
    loff_t pos = 0;
    char* filename;

    ret = old_rename(regs);
    // copy_from_user(filename,(char*)regs->di,2);
    printk("rename File! %d\n",ret);

    // netlink_send_usrmsg(20,200);
    

    return ret;
}

static int __init hook_init(void) {
    netlink_init();
    // 记录原系统调用
    sys_call_table = get_sys_call_table();
    // old_read = (old_syscall_t)sys_call_table[__NR_read];
    // old_write = (old_syscall_t)sys_call_table[__NR_write];
    // old_execve = (old_syscall_t)sys_call_table[__NR_execve];
    old_rename = (old_syscall_t)sys_call_table[__NR_rename];
    // old_unlink = (old_syscall_t)sys_call_table[__NR_unlink];
    // old_unlinkat = (old_syscall_t)sys_call_table[__NR_unlinkat];
    // old_getdents64 = (old_syscall_t)sys_call_table[__NR_getdents64];
    // old_openat = (old_syscall_t)sys_call_table[__NR_openat];
    // 修改内存页权限
    pte = lookup_address((unsigned long)sys_call_table, &level);
    set_pte_atomic(pte, pte_mkwrite(*pte));
    // 写入新的系统调用
    // sys_call_table[__NR_read] = (sys_call_ptr_t)hooked_read;
    // sys_call_table[__NR_write] = (sys_call_ptr_t)hooked_write;
    // sys_call_table[__NR_execve] = (sys_call_ptr_t)hooked_execve;
    sys_call_table[__NR_rename] = (sys_call_ptr_t)hooked_rename;
    // sys_call_table[__NR_unlink] = (sys_call_ptr_t)hooked_unlink;
    // sys_call_table[__NR_unlinkat] = (sys_call_ptr_t)hooked_unlinkat;
    // sys_call_table[__NR_getdents64] = (sys_call_ptr_t)hooked_getdents64;
    // sys_call_table[__NR_openat] = (sys_call_ptr_t)hooked_openat;
    // 恢复内存页权限
    set_pte_atomic(pte, pte_clear_flags(*pte, _PAGE_RW));

    return 0;
}

/**
 * @brief 释放内核模块，恢复原系统调用
 *
 */
static void __exit hook_exit(void) {
    // 修改内存页权限
    set_pte_atomic(pte, pte_mkwrite(*pte));
    // 写回原本的系统调用
    // sys_call_table[__NR_read] = (sys_call_ptr_t)old_read;
    // sys_call_table[__NR_write] = (sys_call_ptr_t)old_write;
    // sys_call_table[__NR_execve] = (sys_call_ptr_t)old_execve;
    sys_call_table[__NR_rename] = (sys_call_ptr_t)old_rename;
    // sys_call_table[__NR_unlink] = (sys_call_ptr_t)old_unlink;
    // sys_call_table[__NR_unlinkat] = (sys_call_ptr_t)old_unlinkat;
    // sys_call_table[__NR_getdents64] = (sys_call_ptr_t)old_getdents64;
    // sys_call_table[__NR_openat] = (sys_call_ptr_t)old_openat;
    // 恢复内存页权限
    set_pte_atomic(pte, pte_clear_flags(*pte, _PAGE_RW));

    // netlink资源回收
    netlink_exit();
}

// 内核模块入/出口注册
module_init(hook_init);
module_exit(hook_exit);