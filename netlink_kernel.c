#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <asm/atomic.h>
#include <linux/semaphore.h>
#include <net/net_namespace.h>
#include <net/netlink.h>

#define NETLINK_TEST 30
#define MSG_LEN 125
#define FILE_MAX_NUM 120

static int pid = 0;
static atomic_t sequence = ATOMIC_INIT(0); // counter原子操作

// 配置定时器频率
DEFINE_RATELIMIT_STATE(rs, 3 * HZ, 1);

// MODULE_LICENSE("GPL");
// MODULE_DESCRIPTION("netlink example");

struct sock *nlsk = NULL;
extern struct net init_net;

typedef struct _data_struct
{
    int i_f;
    char i_s[MSG_LEN];
} data_struct;

typedef struct _kernel_msg
{
    int inode;
    int op; // 操作：read, write, execve, rename...
} kernel_msg;

typedef struct _user_msg
{
    uid_t uid;
    // 0:no protection
    // 1:others only can cat and ls 
    // 2:others only can ls 
    // 3:can't do anything including ls
    int protect_level; // 文件保护等级 

} user_msg;

static int protected_inodes[FILE_MAX_NUM];

/**
 * @brief 消息队列
 * 使用信号量保护的数据队列，保存用户态返回的数据
 * 
 */
static struct queue
{
    uid_t uid[65536];
    int protect_level[65536];
    // 内核信号量
    struct semaphore sem[65536];
} rspbuf;

user_msg *netlink_send_usrmsg(int inode, int op)
{
    struct sk_buff *nl_skb;
    struct nlmsghdr *nlh;
    unsigned short seq;
    int ret;

    /* 创建sk_buff 空间 */
    nl_skb = nlmsg_new(sizeof(kernel_msg), GFP_ATOMIC);
    if (!nl_skb)
    {
        printk("netlink alloc failure\n");
        return NULL;
    }

    /* 设置netlink消息头部 */
    nlh = nlmsg_put(nl_skb, 0, 0, NETLINK_TEST, sizeof(kernel_msg), 0);
    if (nlh == NULL)
    {
        printk("nlmsg_put failaure \n");
        nlmsg_free(nl_skb);
        return NULL;
    }

    /* 拷贝数据发送 */
    seq = atomic_inc_return(&sequence);
    nlh->nlmsg_seq = seq;
    // memcpy(nlmsg_data(nlh), pbuf, len);
    memset((kernel_msg *)NLMSG_DATA(nlh), 0, sizeof(kernel_msg));
    // memcpy(((data_struct *)NLMSG_DATA(nlh))->i_s, pbuf, len);
    ((kernel_msg *)NLMSG_DATA(nlh))->inode = inode;
    ((kernel_msg *)NLMSG_DATA(nlh))->op = op;
    printk("send to user: inode is %d\top is%d\tseq is %d", ((kernel_msg *)NLMSG_DATA(nlh))->inode, ((kernel_msg *)NLMSG_DATA(nlh))->op, seq);
    ret = netlink_unicast(nlsk, nl_skb, pid, 0);

    // 等待用户态返回的数据存入指定的位置
    // 检查数据队列的信号量
    // 最长等待3s，如果服务器没有发送信息则自动终止
    // down_timeout成功获取信号量返回0
    if (down_timeout(&rspbuf.sem[seq], 3 * HZ))
    {
        // 设定打印间隔3s
        if (__ratelimit(&rs))
        {
            pid = 0;
            printk(KERN_NOTICE "netlink terminated!\n");
        }
        return NULL;
    }
    printk("get user message: uid is %d, protect level is %d", rspbuf.uid[seq], rspbuf.protect_level[seq]);
    user_msg received_data;
    // memset(received_data,0,sizeof(user_msg));
    received_data.uid = rspbuf.uid[seq];
    received_data.protect_level = rspbuf.protect_level[seq];
    // printk("get user success!");

    // return rspbuf.data[seq];
    return &received_data;
}

void netlink_send_hello(int inode, int op)
{
    struct sk_buff *nl_skb;
    struct nlmsghdr *nlh;
    unsigned short seq;
    int ret;

    /* 创建sk_buff 空间 */
    nl_skb = nlmsg_new(sizeof(kernel_msg), GFP_ATOMIC);
    if (!nl_skb)
    {
        printk("netlink alloc failure\n");
        return NULL;
    }

    /* 设置netlink消息头部 */
    nlh = nlmsg_put(nl_skb, 0, 0, NETLINK_TEST, sizeof(kernel_msg), 0);
    if (nlh == NULL)
    {
        printk("nlmsg_put failaure \n");
        nlmsg_free(nl_skb);
        return NULL;
    }

    /* 拷贝数据发送 */
    seq = atomic_inc_return(&sequence);
    nlh->nlmsg_seq = seq;
    // memcpy(nlmsg_data(nlh), pbuf, len);
    memset((kernel_msg *)NLMSG_DATA(nlh), 0, sizeof(kernel_msg));
    // memcpy(((data_struct *)NLMSG_DATA(nlh))->i_s, pbuf, len);
    ((kernel_msg *)NLMSG_DATA(nlh))->inode = inode;
    ((kernel_msg *)NLMSG_DATA(nlh))->op = op;
    printk("send to user: inode is %d\top is%d\tseq is %d", ((kernel_msg *)NLMSG_DATA(nlh))->inode, ((kernel_msg *)NLMSG_DATA(nlh))->op, seq);
    ret = netlink_unicast(nlsk, nl_skb, pid, 0);
}

static void netlink_rcv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh = (struct nlmsghdr *)skb->data;
    char *umsg = NULL;
    char *kmsg = "12345678910111213\n";
    printk("receive user msg seq is %d",nlh->nlmsg_seq);

    // 检查收到的数据是否为初始化信号
    if (*(unsigned long *)NLMSG_DATA(nlh) >> 32 != 0xffffffff)
    {
        if (nlh->nlmsg_seq == -1)
        {
            memcpy(protected_inodes, (int *)NLMSG_DATA(nlh), FILE_MAX_NUM*sizeof(int));
            int i =0;
            for (i = 0; i < FILE_MAX_NUM; i++)
            {
                if (protected_inodes[i]==0)
                {
                    printk("protected_inodes[%d]=0, and ((int *)NLMSG_DATA(nlh))[%d]=%d",i,i,((int *)NLMSG_DATA(nlh))[i]);
                    break;
                }
                
            }
               
            printk("Protected Nodes Update! protected_nodes[FILE_MAX_NUM-1]=%d\t%d",protected_inodes[0],((int *)NLMSG_DATA(nlh))[FILE_MAX_NUM-1]);
        }
        else
        {
            // 将用户态回复的数据按照序列号存入对应的位置
            rspbuf.uid[nlh->nlmsg_seq] = ((user_msg *)NLMSG_DATA(nlh))->uid;
            rspbuf.protect_level[nlh->nlmsg_seq] = ((user_msg *)NLMSG_DATA(nlh))->protect_level;
            up(&rspbuf.sem[nlh->nlmsg_seq]); // V操作，sem加一表示当前数据可用
        }
    }
    else
    {

        // 接收到了初始化信号
        // 提取服务器进程的pid保存在全局变量中
        // if (NETLINK_CREDS(skb)->pid == nlh->nlmsg_pid && !NETLINK_CREDS(skb)->uid.val)
        if (1)
        {
            printk(KERN_NOTICE "netlink initiated! length is %ld\n", strlen(kmsg));
            pid = nlh->nlmsg_pid;
            netlink_send_hello(10, 100);
        }
        else
        {
            printk(KERN_NOTICE "initiated fail !!!\n");
        }
    }
}

struct netlink_kernel_cfg cfg = {
    .input = netlink_rcv_msg, /* set recv callback */
};

int netlink_init(void)
{
    /* create netlink socket */
    nlsk = (struct sock *)netlink_kernel_create(&init_net, NETLINK_TEST, &cfg);
    if (nlsk == NULL)
    {
        printk("netlink_kernel_create error !\n");
        return -1;
    }
    printk("test_netlink_init\n");

    // 消息队列初始化
    int i;
    for (i = 0; i < 65536; ++i)
    {
        rspbuf.uid[i] = 0;
        rspbuf.protect_level[i] = 0;
        sema_init(&rspbuf.sem[i], 0);
    }
    for (i = 0; i < FILE_MAX_NUM; i++)
    {
        protected_inodes[i] = 0;
    }

    // 初始化等待时间标志位
    ratelimit_set_flags(&rs, RATELIMIT_MSG_ON_RELEASE);

    return 0;
}

void netlink_exit(void)
{
    if (nlsk)
    {
        netlink_kernel_release(nlsk); /* release ..*/
        nlsk = NULL;
    }
    printk("netlink exit!\n");
}

// module_init(netlink_init);
// module_exit(netlink_exit);