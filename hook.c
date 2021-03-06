//#include "crypto.c"
//#include "netlink.c"
#include <linux/types.h>
#include <linux/dirent.h>
#include <linux/file.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>

MODULE_LICENSE("GPL");

struct linux_dirent {
    unsigned long d_ino;
    unsigned long d_off;
    unsigned short d_reclen;
    char d_name[];
};

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
old_syscall_t old_getdents = NULL;
old_syscall_t old_openat = NULL;

// 系统调用入口地址表的地址
sys_call_ptr_t* sys_call_table = NULL;
pte_t* pte = NULL;
unsigned int level = 0;

/**ASDA
 * @brief 通过文件描述符查询文件的inode号
 * 在操作中排除了字符/块设备文件的访问
 * 
 * @param fd 文件描述符
 * @return unsigned long 文件inode号码
 */
static unsigned long get_ino_from_fd(unsigned int fd) {
    // 通过文件描述符获得文件控制块
    struct fd f = fdget(fd);
    umode_t mode = 0;
    unsigned long ino = 0;

    if (!IS_ERR(f.file)) {
        // 检查文件类型，排除设备文件
        mode = f.file->f_inode->i_mode;
        if (!S_ISCHR(mode) && !S_ISBLK(mode)) {
            ino = f.file->f_inode->i_ino;
        }
        fdput(f);
    }
    //printk("========File ino=====%ld",ino);
    return ino;
}

/**
 * @brief 通过文件名查询文件的inode号
 *
 * @param dfd 指定相对路径对应的基地址，使用AT_FDCWD表示当前路径
 * @param filename 文件名
 * @return unsigned long 文件的inode号
 */
static unsigned long get_ino_from_name(int dfd, const char* filename) {
    struct kstat stat;
    umode_t mode = 0;
    unsigned long ino = 0;
    // 通过文件名获得文件属性
    int error = vfs_statx(dfd, filename, AT_NO_AUTOMOUNT, &stat, STATX_BASIC_STATS);

    if (!error) {
        // 检查文件类型，排除设备文件
        mode = stat.mode;
        if (!S_ISCHR(mode) && !S_ISBLK(mode)) {
            ino = stat.ino;
        }
    }

    return ino;
}

/**
 * @brief 检查当前用户对该文件的权限
 * 返回2：表示文件没有被保护，或者用户有root权限
 * 返回1：表示文件受到保护，当前用户是文件主或为root
 * 返回0：表示文件受到保护，当前用户不是文件主
 * 
 * @param ino 文件的inode号码
 * @param uid 执行操作的用户uid
 * @return unsigned char 权限状态
 */
static unsigned char check_privilege(unsigned long ino, uid_t uid) {
    uid_t owner = 0;
    //0: can read
    //1: not read
    //2: invisible
    int protect=0;
    // unsigned char privilege = 1;

    // if (ino > 10 && uid) {
    //     owner = 1000;
    // }
    // if (owner) {
    //     privilege = (owner == uid) ? 1 : 0;
    // }
    if (uid==owner)
	    return 1;
    else return 0;

    //return privilege;
}

/**
 * @brief 检查该文件是否受到保护
 * 对于重命名和删除等情况，认为加入文件保险箱的文件不能被其他用户重命名或者删除
 * 返回1：文件没有被保护
 * 返回0：文件受到保护，不能被重命名和删除
 * 
 * @param ino
 * @return unsigned char
 */
static unsigned char check_protection(unsigned long ino) {
    //uid_t owner = 0;

    // if (ino > 10) {
    //     owner = get_owner(ino);
    // }
    // // 当文件没有被保护时，用户态返回数据为0
    // return (owner == 0);
    if (ino==277585||ino==277633||ino==277635){
        return 0;
    }
    // if (ino==277635){
    //     return 2;
    // }
    return 1;
}

/**
 * @brief 获得文件上一次读写之后的位置
 * 在随机读写中，为了便于读写的加解密操作，需要获得上一次读写的位置
 *
 * @param fd 读写的文件描述符
 * @param op 处理追加写操作
 * @return loff_t 文件上一次读写的位置
 */
static loff_t get_pos_from_fd(unsigned int fd, unsigned char op) {
    loff_t pos = 0;
    struct fd f = fdget(fd);

    if (f.file) {
        if (op && (f.file->f_flags & O_APPEND)) {
            // 对于追加写操作，设置上次读写位置为文件尾
            struct kstat stat;
            vfs_fstat(fd, &stat);
            pos = stat.size;
        } else {
            pos = f.file->f_pos;
        }
        fdput(f);
    }

    return pos;
}

/*
 * 在Linux 4.18.0-25内核中，系统调用时使用寄存器传递参数的顺序依次为
 * rdi  | rsi   | rdx   | r10
 * 1st  | 2nd   | 3rd   | 4th 
 */

/**
 * @brief 对于系统调用sys_read的重载
 * Linux 4.18.0
 * asmlinkage long sys_read(unsigned int fd, char __user *buf, size_t count);
 * 
 * @param regs 保存各个参数指针的寄存器值
 * @return ssize_t
 */
asmlinkage ssize_t hooked_read(struct pt_regs* regs) {
    unsigned long ino;
    uid_t uid;
    ssize_t ret = -1;
    //loff_t pos = 0;

    // 获得读取文件的信息，文件名保存在rdi中
    ino = get_ino_from_fd(regs->di);
    uid = current_uid().val;
    // 检查访问权限
    // switch (check_privilege(ino, uid)) {
    // case 2:
    //     ret = old_read(regs);
    //     break;
    // case 1:
    //     // 读取文件pos为读取文件的偏移量
    //     // 文件内容读取后保存在rsi中
    //     pos = get_pos_from_fd(regs->di, 0);
    //     ret = old_read(regs);
    //     // 解密
    //     //transform((char*)regs->si, ino, pos, ret);
    //     break;
    // case 0:
    //     ;
    // }
    if (check_protection(ino)) {
        ret = old_read(regs);
    }
    else{
        if(check_privilege(ino,uid))
            ret = old_read(regs);
    }

    return ret;
}

/**
 * @brief 对于系统调用sys_write的重载
 * Linux 4.18.0
 * asmlinkage long sys_write(unsigned int fd, const char __user *buf, size_t count);
 * 
 * @param regs
 * @return ssize_t
 */
asmlinkage ssize_t hooked_write(struct pt_regs* regs) {
    unsigned long ino;
    uid_t uid;
    ssize_t ret = -1;
    // loff_t pos = 0;

    // 获得写文件的信息，文件名位于rdi
    ino = get_ino_from_fd(regs->di);
    uid = current_uid().val;
    // 检查权限
    // switch (check_privilege(ino, uid)) {
    // case 2:
    //     ret = old_write(regs);
    //     break;
    // case 1:
    //     // 找到上次读写的位置
    //     pos = get_pos_from_fd(regs->di, 1);
    //     // 读取rdi加密后写入，写入的字节数存在rdx中
    //     //transform((char*)regs->si, ino, pos, regs->dx);
    //     ret = old_write(regs);
    //     break;
    // case 0:
    //     ;
    // }
    if (check_protection(ino)) {
        ret = old_write(regs);
    }
    else{
        if(check_privilege(ino,uid))
            ret = old_write(regs);
    }

    return ret;
}

/**
 * @brief 对于系统调用sys_write的重载
 * Linux 4.18.0
 * asmlinkage long sys_execve(const char __user *filename,
 *		const char __user *const __user *argv,
 *		const char __user *const __user *envp);
 *
 * @param regs
 * @return ssize_t
 */
asmlinkage ssize_t hooked_execve(struct pt_regs* regs) {
    unsigned long ino;
    uid_t uid;
    ssize_t ret = -1;

    // 获得参数的内容
    // 文件名位于rdi
    ino = get_ino_from_name(AT_FDCWD, (char*)regs->di);
    uid = current_uid().val;
    // 检查权限
    // switch (check_privilege(ino, uid)) {
    // case 2:
    //     ret = old_execve(regs);
    //     break;
    // case 1:
    //     ret = old_execve(regs);
    //     break;
    // case 0:
    //     ;
    // }
    if (check_protection(ino)) {
        ret = old_execve(regs);
    }
    else{
        if(check_privilege(ino,uid))
            ret = old_execve(regs);
    }

    return ret;
}

/**
 * @brief 对于系统调用sys_rename的重载
 * Linux 4.18.0
 * asmlinkage long sys_rename(const char __user *oldname,
 *				const char __user *newname);
 * 
 * @param regs
 * @return ssize_t
 */
// Linux内核中的系统调用包括sys_rename, sys_renameat, sys_renameat2
// TODO：检查是否有必要重载另外的几个函数
asmlinkage ssize_t hooked_rename(struct pt_regs* regs) {
    unsigned long ino;
    uid_t uid;
    ssize_t ret = -1;
	printk("Sec_rename");
    uid = current_uid().val;
    // Magic! Do not Modify!
    // Test 'mv' Command:
    //   使用rdi(oldname)，不管是本用户还是其他用户都是not permitted
    //   使用rsi(newname)，本用户可以正常修改，其他用户无法修改
    ino = get_ino_from_name(AT_FDCWD, (char*)regs->di);
    if (check_protection(ino)) {
        ret = old_rename(regs);
    }
    else{
        if(check_privilege(ino,uid))
            ret = old_rename(regs);
    }

    return ret;
}

/**
 * @brief 对于系统调用sys_unlink的重载
 * Linux 4.18.0
 * asmlinkage long sys_unlink(const char __user *pathname);
 * 
 * @param regs
 * @return ssize_t
 */
asmlinkage ssize_t hooked_unlink(struct pt_regs* regs) {
    unsigned long ino;
    ssize_t ret = -1;
    uid_t uid;
    uid = current_uid().val;

    // 从rdi中读取文件名获得inode
    ino = get_ino_from_name(AT_FDCWD, (char*)regs->di);
    if (check_protection(ino)) {
        ret = old_unlink(regs);
    }
    else{
        if(check_privilege(ino,uid))
            ret = old_unlink(regs);
    }

    return ret;
}

/**
 * @brief 对于系统调用sys_unlinkat的重载
 * Linux 4.18.0
 * asmlinkage long sys_unlinkat(int dfd, const char __user * pathname, int flag);
 * 
 * @param regs
 * @return ssize_t
 */
asmlinkage ssize_t hooked_unlinkat(struct pt_regs* regs) {
    unsigned long ino;
    ssize_t ret = -1;
    uid_t uid;
    uid = current_uid().val;

    // 从rsi中读取文件名以获得inode号
    ino = get_ino_from_name(regs->di, (char*)regs->si);
    if (check_protection(ino)) {
        ret = old_unlinkat(regs);
    }
    else{
        if(check_privilege(ino,uid))
            ret = old_unlinkat(regs);
    }

    return ret;
}

/**
 * @brief 对于系统调用sys_getdents64的重载
 * Linux 4.18.0
 * asmlinkage long sys_getdents64(unsigned int fd,
 *				struct linux_dirent64 __user *dirent,
 *				unsigned int count);
 * 
 * @param regs
 * @return ssize_t
 */
// Linux内核中的系统调用还包括sys_getdents
// TODO：是否有必要重载sys_getdents
asmlinkage ssize_t hooked_getdents64(struct pt_regs* regs) {
    uid_t uid;
    ssize_t ret = -1;
    int copylen = 0;
    // 创建指针用于处理目录项
    struct linux_dirent64 *filtered_dirent;
    struct linux_dirent64 *orig_dirent;
    struct linux_dirent64 *td1;
    struct linux_dirent64 *td2;

    uid = current_uid().val;
    // printk("hooked_ls");
    // 使用原系统调用
    ret = old_getdents64(regs);

    // 处理空文件
    if (ret == 0) return ret;

    // 申请内核的内存空间
    filtered_dirent = (struct linux_dirent64*)kmalloc(ret, GFP_KERNEL);
    td1 = filtered_dirent;
    orig_dirent = (struct linux_dirent64*)kmalloc(ret, GFP_KERNEL);
    td2 = orig_dirent;
    // 将目录项复制到内核空间
    copy_from_user(orig_dirent, (void *)regs->si, ret);
    // printk("====origin length=================:%ld",ret);
    // 迭代检查目录项
    while (ret > 0) {
        ret -= td2->d_reclen;
        
        //被隐藏无法访问
        if (check_protection(td2->d_ino)) {
	    // printk("Inode --- %d UID --- %d",(int)td2->d_ino,(int)uid);
            memmove(td1, (char *)td2, td2->d_reclen);
            td1 = (struct linux_dirent64*)((char *)td1 + td2->d_reclen);
            copylen += td2->d_reclen;
        }

        // 目录项通过检查

        td2 = (struct linux_dirent64*)((char *)td2 + td2->d_reclen);
    }
    // printk("====copy length=================:%d",copylen);

    // 目录项复制回到用户空间
    copy_to_user((void *)regs->si, filtered_dirent, copylen);
    // 释放内核态内存空间
    kfree(orig_dirent);
    kfree(filtered_dirent);

    return copylen;
}

asmlinkage ssize_t hooked_getdents(struct pt_regs* regs) {
    uid_t uid;
    ssize_t ret = -1;
    int copylen = 0;
    // 创建指针用于处理目录项
    struct linux_dirent *filtered_dirent;
    struct linux_dirent *orig_dirent;
    struct linux_dirent *td1;
    struct linux_dirent *td2;

    uid = current_uid().val;
    // printk("hooked_ls");
    //使用原系统调用
    ret = old_getdents(regs);

    // 处理空文件
    if (ret == 0) return ret;

    // 申请内核的内存空间
    filtered_dirent = (struct linux_dirent*)kmalloc(ret, GFP_KERNEL);
    td1 = filtered_dirent;
    orig_dirent = (struct linux_dirent*)kmalloc(ret, GFP_KERNEL);
    td2 = orig_dirent;
    // 将目录项复制到内核空间
    copy_from_user(orig_dirent, (void *)regs->si, ret);
    // printk("====origin length=================:%ld",ret);
    // 迭代检查目录项
    while (ret > 0) {
        ret -= td2->d_reclen;
        
        //被隐藏无法访问
        if (check_protection(td2->d_ino)) {
	    // printk("Inode --- %d UID --- %d",(int)td2->d_ino,(int)uid);
            memmove(td1, (char *)td2, td2->d_reclen);
            td1 = (struct linux_dirent*)((char *)td1 + td2->d_reclen);
            copylen += td2->d_reclen;
        }

        // 目录项通过检查

        td2 = (struct linux_dirent*)((char *)td2 + td2->d_reclen);
    }
    // printk("====copy length=================:%d",copylen);

    // 目录项复制回到用户空间
    copy_to_user((void *)regs->si, filtered_dirent, copylen);
    // 释放内核态内存空间
    kfree(orig_dirent);
    kfree(filtered_dirent);

    return copylen;
    //return -1;
}


/**
 * @brief 对于系统调用sys_openat的重载
 * Linux 4.18.0
 * asmlinkage long sys_openat(int dfd, const char __user *filename, int flags,
 *			   umode_t mode);
 * 
 * @param regs
 * @return ssize_t
 */
// Linux中的系统调用包括sys_open
// TODO：考虑是否有必要重载sys_open
asmlinkage ssize_t hooked_openat(struct pt_regs* regs) {
    unsigned long ino;
    uid_t uid;
    ssize_t ret = -1;

    // 获得inode节点
    ino = get_ino_from_name(regs->di, (char*)regs->si);
    uid = current_uid().val;
    if (check_protection(ino)) {
        ret = old_openat(regs);
    }
    else{
        if(check_privilege(ino,uid))
            ret = old_openat(regs);
    }

    return ret;
}

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

/**
 * @brief 初始化内核模块，实现系统调用重载
 *
 * @return int
 */
static int __init hook_init(void) {
    // netlink初始化
    //netlink_init();

    // 记录原系统调用
    sys_call_table = get_sys_call_table();
    old_read = (old_syscall_t)sys_call_table[__NR_read];
    old_write = (old_syscall_t)sys_call_table[__NR_write];
    old_execve = (old_syscall_t)sys_call_table[__NR_execve];
    old_rename = (old_syscall_t)sys_call_table[__NR_rename];
    old_unlink = (old_syscall_t)sys_call_table[__NR_unlink];
    old_unlinkat = (old_syscall_t)sys_call_table[__NR_unlinkat];
    old_getdents64 = (old_syscall_t)sys_call_table[__NR_getdents64];
    old_getdents = (old_syscall_t)sys_call_table[__NR_getdents];
    old_openat = (old_syscall_t)sys_call_table[__NR_openat];
    // 修改内存页权限
    pte = lookup_address((unsigned long)sys_call_table, &level);
    set_pte_atomic(pte, pte_mkwrite(*pte));
    // 写入新的系统调用
    sys_call_table[__NR_read] = (sys_call_ptr_t)hooked_read;
    sys_call_table[__NR_write] = (sys_call_ptr_t)hooked_write;
    sys_call_table[__NR_execve] = (sys_call_ptr_t)hooked_execve;
    sys_call_table[__NR_rename] = (sys_call_ptr_t)hooked_rename;
    sys_call_table[__NR_unlink] = (sys_call_ptr_t)hooked_unlink;
    sys_call_table[__NR_unlinkat] = (sys_call_ptr_t)hooked_unlinkat;
    sys_call_table[__NR_getdents64] = (sys_call_ptr_t)hooked_getdents64;
    sys_call_table[__NR_getdents] = (sys_call_ptr_t)hooked_getdents;
    sys_call_table[__NR_openat] = (sys_call_ptr_t)hooked_openat;
    // 恢复内存页权限
    set_pte_atomic(pte, pte_clear_flags(*pte, _PAGE_RW));

    return 0;
}

/**
 * @brief 释放内核模块，恢复原系统调用
 *
 */
static void __exit hook_exit(void) {
    printk("Exit!!!!");
    // 修改内存页权限
    set_pte_atomic(pte, pte_mkwrite(*pte));
    // 写回原本的系统调用
    sys_call_table[__NR_read] = (sys_call_ptr_t)old_read;
    sys_call_table[__NR_write] = (sys_call_ptr_t)old_write;
    sys_call_table[__NR_execve] = (sys_call_ptr_t)old_execve;
    sys_call_table[__NR_rename] = (sys_call_ptr_t)old_rename;
    sys_call_table[__NR_unlink] = (sys_call_ptr_t)old_unlink;
    sys_call_table[__NR_unlinkat] = (sys_call_ptr_t)old_unlinkat;
    sys_call_table[__NR_getdents64] = (sys_call_ptr_t)old_getdents64;
    sys_call_table[__NR_getdents] = (sys_call_ptr_t)old_getdents;
    sys_call_table[__NR_openat] = (sys_call_ptr_t)old_openat;
    // 恢复内存页权限
    set_pte_atomic(pte, pte_clear_flags(*pte, _PAGE_RW));

    // netlink资源回收
    //netlink_exit();
}

// 内核模块入/出口注册
module_init(hook_init);
module_exit(hook_exit);