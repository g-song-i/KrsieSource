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
struct data_t {
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

    // new socket
    u32 new_socket_state;
    u32 new_socket_type; 
    u32 new_socket_flags;
    
    u16 local_port;
    u32 local_address;

    u32 mntns;
    // sockaddr 
};

typedef struct network_connection_v4 {
    u32 local_address;
    u16 local_port;
    u32 remote_address;
    u16 remote_port;
} net_conn_v4_t;

/* Supported address families. */
#define AF_UNSPEC	0
#define AF_UNIX		1	/* Unix domain sockets 		*/
#define AF_LOCAL	1	/* POSIX name for AF_UNIX	*/
#define AF_INET		2	/* Internet IP Protocol 	*/
#define AF_AX25		3	/* Amateur Radio AX.25 		*/
#define AF_IPX		4	/* Novell IPX 			*/
#define AF_APPLETALK	5	/* AppleTalk DDP 		*/
#define AF_NETROM	6	/* Amateur Radio NET/ROM 	*/
#define AF_BRIDGE	7	/* Multiprotocol bridge 	*/
#define AF_ATMPVC	8	/* ATM PVCs			*/
#define AF_X25		9	/* Reserved for X.25 project 	*/
#define AF_INET6	10	/* IP version 6			*/
#define AF_ROSE		11	/* Amateur Radio X.25 PLP	*/
#define AF_DECnet	12	/* Reserved for DECnet project	*/
#define AF_NETBEUI	13	/* Reserved for 802.2LLC project*/
#define AF_SECURITY	14	/* Security callback pseudo AF */
#define AF_KEY		15      /* PF_KEY key management API */
#define AF_NETLINK	16
#define AF_ROUTE	AF_NETLINK /* Alias to emulate 4.4BSD */
#define AF_PACKET	17	/* Packet family		*/
#define AF_ASH		18	/* Ash				*/
#define AF_ECONET	19	/* Acorn Econet			*/
#define AF_ATMSVC	20	/* ATM SVCs			*/
#define AF_RDS		21	/* RDS sockets 			*/
#define AF_SNA		22	/* Linux SNA Project (nutters!) */
#define AF_IRDA		23	/* IRDA sockets			*/
#define AF_PPPOX	24	/* PPPoX sockets		*/
#define AF_WANPIPE	25	/* Wanpipe API Sockets */
#define AF_LLC		26	/* Linux LLC			*/
#define AF_IB		27	/* Native InfiniBand address	*/
#define AF_MPLS		28	/* MPLS */
#define AF_CAN		29	/* Controller Area Network      */
#define AF_TIPC		30	/* TIPC sockets			*/
#define AF_BLUETOOTH	31	/* Bluetooth sockets 		*/
#define AF_IUCV		32	/* IUCV sockets			*/
#define AF_RXRPC	33	/* RxRPC sockets 		*/
#define AF_ISDN		34	/* mISDN sockets 		*/
#define AF_PHONET	35	/* Phonet sockets		*/
#define AF_IEEE802154	36	/* IEEE802154 sockets		*/
#define AF_CAIF		37	/* CAIF sockets			*/
#define AF_ALG		38	/* Algorithm sockets		*/
#define AF_NFC		39	/* NFC sockets			*/
#define AF_VSOCK	40	/* vSockets			*/
#define AF_KCM		41	/* Kernel Connection Multiplexor*/
#define AF_QIPCRTR	42	/* Qualcomm IPC Router          */
#define AF_SMC		43	/* smc sockets: reserve number for
				 * PF_SMC protocol family that
				 * reuses AF_INET address family
				 */
#define AF_XDP		44	/* XDP sockets			*/

#define AF_MAX		45	/* For now.. */

/*
 * Create a buffer for sending event data to userspace
 */
BPF_PERF_OUTPUT(events);

/* Functions */
#define READ_KERN(ptr)                                                  \
    ({                                                                  \
        typeof(ptr) _val;                                               \
        __builtin_memset((void *)&_val, 0, sizeof(_val));               \
        bpf_probe_read((void *)&_val, sizeof(_val), &ptr);              \
        _val;                                                           \
    })


static __always_inline u32 get_inet_rcv_saddr(struct inet_sock *inet)
{
    return READ_KERN(inet->inet_rcv_saddr);
}

static __always_inline u32 get_inet_saddr(struct inet_sock *inet)
{
    return READ_KERN(inet->inet_saddr);
}

static __always_inline u32 get_inet_daddr(struct inet_sock *inet)
{
    return READ_KERN(inet->inet_daddr);
}

static __always_inline u16 get_inet_sport(struct inet_sock *inet)
{
    return READ_KERN(inet->inet_sport);
}

static __always_inline u16 get_inet_num(struct inet_sock *inet)
{
    return READ_KERN(inet->inet_num);
}

static __always_inline u16 get_inet_dport(struct inet_sock *inet)
{
    return READ_KERN(inet->inet_dport);
}

static __always_inline struct sock* get_socket_sock(struct socket *socket)
{
    return READ_KERN(socket->sk);
}

static __always_inline u16 get_sock_family(struct sock *sock)
{
    return READ_KERN(sock->sk_family);
}

static __always_inline u16 get_sock_protocol(struct sock *sock)
{
    u16 protocol = 0;

#ifndef CORE
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0))
    // kernel 4.18-5.5: sk_protocol bit-field: use sk_gso_max_segs field and go
    // back 24 bits to reach sk_protocol field index.
    bpf_probe_read(&protocol, 1, (void *)(&sock->sk_gso_max_segs) - 3);
#else
    // kernel 5.6
    protocol = READ_KERN(sock->sk_protocol);
#endif
#else // CORE
    // commit bf9765145b85 ("sock: Make sk_protocol a 16-bit value")
    struct sock___old *check = NULL;
    if (bpf_core_field_exists(check->__sk_flags_offset)) {
        check = (struct sock___old *) sock;
        bpf_core_read(&protocol, 1, (void *)(&check->sk_gso_max_segs) - 3);
    } else {
        protocol = READ_KERN(sock->sk_protocol);
    }
#endif

    return protocol;
}

static __always_inline u16 get_sockaddr_family(struct sockaddr *address)
{
    return READ_KERN(address->sa_family);
}

static __always_inline struct in6_addr get_sock_v6_rcv_saddr(struct sock *sock)
{
    return READ_KERN(sock->sk_v6_rcv_saddr);
}

static __always_inline struct in6_addr get_ipv6_pinfo_saddr(struct ipv6_pinfo *np)
{
    return READ_KERN(np->saddr);
}

static __always_inline u32 get_ipv6_pinfo_flow_label(struct ipv6_pinfo *np)
{
    return READ_KERN(np->flow_label);
}

static __always_inline struct in6_addr get_sock_v6_daddr(struct sock *sock)
{
    return READ_KERN(sock->sk_v6_daddr);
}

static __always_inline int get_sock_bound_dev_if(struct sock *sock)
{
    return READ_KERN(sock->sk_bound_dev_if);
}

static __always_inline volatile unsigned char get_sock_state(struct sock *sock)
{
    volatile unsigned char sk_state_own_impl;
    bpf_probe_read((void *)&sk_state_own_impl, sizeof(sk_state_own_impl), (const void *)&sock->sk_state);
    return sk_state_own_impl;
}

static __always_inline struct ipv6_pinfo* get_inet_pinet6(struct inet_sock *inet)
{
    struct ipv6_pinfo *pinet6_own_impl;
    bpf_probe_read(&pinet6_own_impl, sizeof(pinet6_own_impl), &inet->pinet6);
    return pinet6_own_impl;
}

static __always_inline struct sockaddr_un get_unix_sock_addr(struct unix_sock *sock)
{
    struct unix_address* addr = READ_KERN(sock->addr);
    int len = READ_KERN(addr->len);
    struct sockaddr_un sockaddr = {};
    if (len <= sizeof(struct sockaddr_un)) {
        bpf_probe_read(&sockaddr, len, addr->name);
    }
    return sockaddr;
}
 
 static __always_inline int get_network_details_from_sock_v4(struct sock *sk, net_conn_v4_t *net_details, int peer)
{
    struct inet_sock *inet = inet_sk(sk);

    if (!peer) {
        net_details->local_address = get_inet_rcv_saddr(inet);
        net_details->local_port = bpf_ntohs(get_inet_num(inet));
        net_details->remote_address = get_inet_daddr(inet);
        net_details->remote_port = get_inet_dport(inet);
    }
    else {
        net_details->remote_address = get_inet_rcv_saddr(inet);
        net_details->remote_port = bpf_ntohs(get_inet_num(inet));
        net_details->local_address = get_inet_daddr(inet);
        net_details->local_port = get_inet_dport(inet);
    }

    return 0;
}
/* End Functions */

/* Container filtering */

struct mnt_namespace {
    // This field was removed in https://github.com/torvalds/linux/commit/1a7b8969e664d6af328f00fe6eb7aabd61a71d13
    #if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
        atomic_t count;
    #endif
        struct ns_common ns;
};

static inline int _mntns_filter(unsigned int mntnsid) {
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

static inline int container_should_be_filtered(unsigned int mntnsid) {
        return _mntns_filter(mntnsid);
}

/* End Container filtering */

/*
 * Attach to the "socket_accept" LSM hook
 */
LSM_PROBE(socket_accept, struct socket *sock, struct socket *newsock) {
    /*
    * Filter container first 
    */
    if(!container_should_be_filtered(MOUNT_NS_ID))
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
    // Ref: https://github.com/aquasecurity/tracee/blob/main/pkg/ebpf/c/tracee.bpf.c#L3392
    struct sock *sk = get_socket_sock(sock);

    // GET IPv4 only
    net_conn_v4_t net_details = {};
    get_network_details_from_sock_v4(sk, &net_details, 0);
 
    data.socket_state = sock->state;
    data.socket_type = sock->type; 
    data.socket_flags = sock->flags;

    data.new_socket_state = newsock->state;
    data.new_socket_type = newsock->type; 
    data.new_socket_flags = newsock->flags;

    data.local_port = net_details.local_port;
    data.local_address = net_details.local_address;

    /* Tracing/Monitoring log */
    events.perf_submit(ctx, &data, sizeof(data));


    if(CONDITIONS) {
        return ACTION;
    }
    return INVERSE;
}
