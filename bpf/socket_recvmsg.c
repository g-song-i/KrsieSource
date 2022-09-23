/* ################################
 * static inline int
 * Author: PHUCDT
 * Date: 4/6/2022
 * Params: DATA_T_MORE_INFORMATION, MOUNT_NS_ID, CONDITIONS, ACTION
 * ################################
 */

#include <linux/security.h>
#include <linux/nsproxy.h>
#include <linux/mount.h>
#include <linux/ns_common.h>
#include <linux/errno.h>
#include <linux/errno.h>
#include <linux/socket.h>
#include <linux/net.h>

#include <net/af_unix.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/ipv6.h>
#include <net/tcp_states.h>
#include <linux/ipv6.h>
#include <uapi/linux/icmp.h>
#include <uapi/linux/icmpv6.h>

#define __LOWER(x) (x & 0xffffffff)
#define __UPPER(x) (x >> 32)

/*
 * Create a data structure for collecting event data
 */
struct data_t
{
    char comm[TASK_COMM_LEN];
    char pcomm[TASK_COMM_LEN];
    u32 uid;
    u32 gid;
    u32 pid;
    u32 ppid;
    // socket
    u32 socket_state;
    u32 socket_type;
    u32 socket_flags;

    u32 remote_address;
    u16 remote_port;
    u16 size;
    u16 flags;
    u16 sport;

    u32 mntns;
};

/* Supported address families. */
#define AF_UNSPEC 0
#define AF_UNIX 1      /* Unix domain sockets 		*/
#define AF_LOCAL 1     /* POSIX name for AF_UNIX	*/
#define AF_INET 2      /* Internet IP Protocol 	*/
#define AF_AX25 3      /* Amateur Radio AX.25 		*/
#define AF_IPX 4       /* Novell IPX 			*/
#define AF_APPLETALK 5 /* AppleTalk DDP 		*/
#define AF_NETROM 6    /* Amateur Radio NET/ROM 	*/
#define AF_BRIDGE 7    /* Multiprotocol bridge 	*/
#define AF_ATMPVC 8    /* ATM PVCs			*/
#define AF_X25 9       /* Reserved for X.25 project 	*/
#define AF_INET6 10    /* IP version 6			*/
#define AF_ROSE 11     /* Amateur Radio X.25 PLP	*/
#define AF_DECnet 12   /* Reserved for DECnet project	*/
#define AF_NETBEUI 13  /* Reserved for 802.2LLC project*/
#define AF_SECURITY 14 /* Security callback pseudo AF */
#define AF_KEY 15      /* PF_KEY key management API */
#define AF_NETLINK 16
#define AF_ROUTE AF_NETLINK /* Alias to emulate 4.4BSD */
#define AF_PACKET 17        /* Packet family		*/
#define AF_ASH 18           /* Ash				*/
#define AF_ECONET 19        /* Acorn Econet			*/
#define AF_ATMSVC 20        /* ATM SVCs			*/
#define AF_RDS 21           /* RDS sockets 			*/
#define AF_SNA 22           /* Linux SNA Project (nutters!) */
#define AF_IRDA 23          /* IRDA sockets			*/
#define AF_PPPOX 24         /* PPPoX sockets		*/
#define AF_WANPIPE 25       /* Wanpipe API Sockets */
#define AF_LLC 26           /* Linux LLC			*/
#define AF_IB 27            /* Native InfiniBand address	*/
#define AF_MPLS 28          /* MPLS */
#define AF_CAN 29           /* Controller Area Network      */
#define AF_TIPC 30          /* TIPC sockets			*/
#define AF_BLUETOOTH 31     /* Bluetooth sockets 		*/
#define AF_IUCV 32          /* IUCV sockets			*/
#define AF_RXRPC 33         /* RxRPC sockets 		*/
#define AF_ISDN 34          /* mISDN sockets 		*/
#define AF_PHONET 35        /* Phonet sockets		*/
#define AF_IEEE802154 36    /* IEEE802154 sockets		*/
#define AF_CAIF 37          /* CAIF sockets			*/
#define AF_ALG 38           /* Algorithm sockets		*/
#define AF_NFC 39           /* NFC sockets			*/
#define AF_VSOCK 40         /* vSockets			*/
#define AF_KCM 41           /* Kernel Connection Multiplexor*/
#define AF_QIPCRTR 42       /* Qualcomm IPC Router          */
#define AF_SMC 43           /* smc sockets: reserve number for \
                             * PF_SMC protocol family that     \
                             * reuses AF_INET address family   \
                             */
#define AF_XDP 44           /* XDP sockets			*/

#define AF_MAX 45 /* For now.. */
/*
 * Create a buffer for sending event data to userspace
 */
BPF_PERF_OUTPUT(events);

/* Functions */
#define READ_KERN(ptr)                                     \
    ({                                                     \
        typeof(ptr) _val;                                  \
        __builtin_memset((void *)&_val, 0, sizeof(_val));  \
        bpf_probe_read((void *)&_val, sizeof(_val), &ptr); \
        _val;                                              \
    })

/* End Functions */

/* Container filtering */

struct mnt_namespace
{
// This field was removed in https://github.com/torvalds/linux/commit/1a7b8969e664d6af328f00fe6eb7aabd61a71d13
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
    atomic_t count;
#endif
    struct ns_common ns;
};

static inline int _mntns_filter(unsigned int mntnsid)
{
    struct task_struct *current_task;
    struct nsproxy *nsproxy;
    struct mnt_namespace *mnt_ns;
    unsigned int inum;

    current_task = (struct task_struct *)bpf_get_current_task();
    if (bpf_probe_read_kernel(&nsproxy, sizeof(nsproxy), &current_task->nsproxy))
        return 0;
    if (bpf_probe_read_kernel(&mnt_ns, sizeof(mnt_ns), &nsproxy->mnt_ns))
        return 0;
    if (bpf_probe_read_kernel(&inum, sizeof(inum), &mnt_ns->ns.inum))
        return 0;
    return inum == mntnsid;
}

static inline int container_should_be_filtered(unsigned int mntnsid)
{
    return _mntns_filter(mntnsid);
}

/* End Container filtering */

/*
 * Attach to the "socket_recvmsg" LSM hook
 */
LSM_PROBE(socket_recvmsg, struct socket *sock, struct msghdr *msg,
          int size, int flags)
{
    /*
     * Filter container first
     */
    if (!container_should_be_filtered(MOUNT_NS_ID))
        return 0;

    u64 gid_uid;
    u64 pid_tgid;
    struct data_t data = {};
    /*
     * Gather event data
     */
    gid_uid = bpf_get_current_uid_gid();
    pid_tgid = bpf_get_current_pid_tgid();

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.uid = __LOWER(gid_uid);
    data.gid = __UPPER(gid_uid);
    data.pid = __UPPER(pid_tgid);

    /*
     * GET request protection opt and real protect opt
     */
    data.socket_state = sock->state;
    data.socket_type = sock->type;
    data.socket_flags = sock->flags;
    data.size = size;
    data.flags = flags;

    /* GET source port from sock */
    struct sock *sk = sock->sk;
    struct inet_sock *inet = inet_sk(sk);
    bpf_probe_read_kernel(&data.sport,sizeof(u16),&inet->inet_sport);
    data.sport=htons(data.sport);
    
    /* Tracing/Monitoring log */
    events.perf_submit(ctx, &data, sizeof(data));

    if (CONDITIONS)
    {
        return ACTION;
    }
    return INVERSE;
}
