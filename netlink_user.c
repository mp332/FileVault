#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <linux/netlink.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>

#define NETLINK_TEST 30
#define MSG_LEN 125
#define MAX_PLOAD 1024
#define FILE_MAX_NUM 120

static int protected_inodes[FILE_MAX_NUM];


typedef struct _kernel_msg
{
    int inode;
    int op; // 操作：read, write, execve, rename...
} kernel_msg;

typedef struct _user_msg
{
    uid_t uid;
    int protect_level; // 文件保护等级
} user_msg;

int main(int argc, char **argv)
{
    // netlink协议使用sockaddr_nl地址
    struct sockaddr_nl src_sockaddr, dest_sockaddr;
    struct nlmsghdr *nlh = NULL;
    struct msghdr msg;
    struct iovec iov;
    int server_sock;
    char *umsg = "hello netlink!!";

    int update_inodes = 0;

    int i;
    for (i = 0; i < FILE_MAX_NUM; i++)
    {
        protected_inodes[i] = 123;
    }
    

    // 创建地址并初始化
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PLOAD));
    memset(&src_sockaddr, 0, sizeof(struct sockaddr_nl));
    memset(&dest_sockaddr, 0, sizeof(struct sockaddr_nl));
    memset(nlh, 0, NLMSG_SPACE(MAX_PLOAD));
    memset(&msg, 0, sizeof(struct msghdr));

    // 创建netlink的socket
    server_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_TEST);
    // 创建用户态地址，pid需要设置为进程的pid
    // 实际上是一个socket标识，不同线程可以设置为不同的值
    // groups为多播组，设置为0表示不加入多播
    src_sockaddr.nl_family = AF_NETLINK;
    src_sockaddr.nl_pid = getpid();
    src_sockaddr.nl_groups = 0;
    // 绑定socket和地址
    bind(server_sock, (struct sockaddr *)&src_sockaddr, sizeof(struct sockaddr_nl));
    // 设置核心态用户地址，核心态的pid必须设置为0
    dest_sockaddr.nl_family = AF_NETLINK;
    dest_sockaddr.nl_pid = 0;
    dest_sockaddr.nl_groups = 0;
    // 设置netlink socket的信息头部
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PLOAD);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;
    // 设置iov 可以把多个信息通过一次系统调用发送
    iov.iov_base = (void *)nlh;
    // iov.iov_len = NLMSG_SPACE(sizeof(unsigned long));
    iov.iov_len = nlh->nlmsg_len;
    // 设置接收地址
    msg.msg_name = (void *)&dest_sockaddr;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    // 填充并发送初始化就绪数据
    *(unsigned long *)NLMSG_DATA(nlh) = (unsigned long)0xffffffff << 32;
    // memcpy(NLMSG_DATA(nlh), umsg, strlen(umsg));
    sendmsg(server_sock, &msg, 0);
    int seq;

    while (1)
    {
        // memset((char*)NLMSG_DATA(nlh),0,1024);
        
        
        recvmsg(server_sock, &msg, 0);
        printf("Got response inode is %d\tthe op is %d, seq is %d\n", ((kernel_msg *)NLMSG_DATA(nlh))->inode, ((kernel_msg *)NLMSG_DATA(nlh))->op, nlh->nlmsg_seq);
        seq = nlh->nlmsg_seq;
        
        printf("Current update_inodes is %d\n",update_inodes);
        if (update_inodes>0)
        {
            nlh->nlmsg_seq = -1;
            memcpy((int *)NLMSG_DATA(nlh),protected_inodes,FILE_MAX_NUM*sizeof(int));
            printf("data[FILE_MAX_NUM-1]:%d\n",((int *)NLMSG_DATA(nlh))[FILE_MAX_NUM-1]);
            sendmsg(server_sock, &msg, 0);
            update_inodes=-5;
        }
        update_inodes++;
        // find_owner(inode,op)
        //      select owner from fvalut where inode = %u 
        //      select protect_level from fvalut where inode = %u
        //      audit(inode,owner,protect_level,op)
        // return owner,protect_level;
        // 
        // void audit(inode,owner,protect_level,op)
        //      current_uid = get_uid() 知道当前用户 
        //      审计：owner != current_uid op 知道结果，insert into faudit ...
        user_msg u_s;
        u_s.protect_level = 8;
        u_s.uid = 99;
        memset((user_msg *)NLMSG_DATA(nlh), 0, sizeof(user_msg));
        ((user_msg *)NLMSG_DATA(nlh))->protect_level = u_s.protect_level;
        ((user_msg *)NLMSG_DATA(nlh))->uid = u_s.uid;
        nlh->nlmsg_seq = seq;
        sendmsg(server_sock, &msg, 0);
        printf("send to kernel message: owner is %d\tprotect level is %d\tseq is %d\n", u_s.uid, u_s.protect_level, nlh->nlmsg_seq);
    }

    return 0;
}