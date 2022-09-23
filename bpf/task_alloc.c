/* ################################
 * Author: Songi Gwak
 * Date: 5/01/2022
 * Params: DATA_T_MORE_INFORMATION, MOUNT_NS_ID, CONDITIONS, ACTION
 * ################################
 */

#include <linux/security.h>
#include <linux/nsproxy.h>
#include <linux/mount.h>
#include <linux/ns_common.h>
#include <linux/errno.h>

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

    u64 clone_flags;
    u32 parent_tid;
    u32 parent_tgid;
    u32 child_tid;
    u32 child_tgid;
    u32 newsp;
    u32 stack_size;
    // the TLS (Thread Local Storage) descriptor is set to tls. especially, TLS here means location of new TLS
    //u32 tls;

    u32 mntns;
};

/*
 * cloning flags:
 */
#define CSIGNAL		0x000000ff	/* signal mask to be sent at exit */
#define CLONE_VM	0x00000100	/* set if VM shared between processes */
#define CLONE_FS	0x00000200	/* set if fs info shared between processes */
#define CLONE_FILES	0x00000400	/* set if open files shared between processes */
#define CLONE_SIGHAND	0x00000800	/* set if signal handlers and blocked signals shared */
#define CLONE_PIDFD	0x00001000	/* set if a pidfd should be placed in parent */
#define CLONE_PTRACE	0x00002000	/* set if we want to let tracing continue on the child too */
#define CLONE_VFORK	0x00004000	/* set if the parent wants the child to wake it up on mm_release */
#define CLONE_PARENT	0x00008000	/* set if we want to have the same parent as the cloner */
#define CLONE_THREAD	0x00010000	/* Same thread group? */
#define CLONE_NEWNS	0x00020000	/* New mount namespace group */
#define CLONE_SYSVSEM	0x00040000	/* share system V SEM_UNDO semantics */
#define CLONE_SETTLS	0x00080000	/* create a new TLS for the child */
#define CLONE_PARENT_SETTID	0x00100000	/* set the TID in the parent */
#define CLONE_CHILD_CLEARTID	0x00200000	/* clear the TID in the child */
#define CLONE_DETACHED		0x00400000	/* Unused, ignored */
#define CLONE_UNTRACED		0x00800000	/* set if the tracing process can't force CLONE_PTRACE on this clone */
#define CLONE_CHILD_SETTID	0x01000000	/* set the TID in the child */
#define CLONE_NEWCGROUP		0x02000000	/* New cgroup namespace */
#define CLONE_NEWUTS		0x04000000	/* New utsname namespace */
#define CLONE_NEWIPC		0x08000000	/* New ipc namespace */
#define CLONE_NEWUSER		0x10000000	/* New user namespace */
#define CLONE_NEWPID		0x20000000	/* New pid namespace */
#define CLONE_NEWNET		0x40000000	/* New network namespace */
#define CLONE_IO		0x80000000	/* Clone io context */

/*
 * Create a buffer for sending event data to userspace
 */
BPF_PERF_OUTPUT(events);

/* Functions */
 
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
 * Attach to the "task_alloc" LSM hook
 */
LSM_PROBE(task_alloc, struct task_struct *task, unsigned long clone_flags) {
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

    data.clone_flags = clone_flags;
    data.child_tid = task->pid;
    data.child_tgid = task->tgid;
    data.parent_tid = task->real_parent->pid;
    data.parent_tgid = task->real_parent->tgid;

    data.newsp = task->curr_ret_stack;
    data.stack_size = task->curr_ret_depth;

    /* Tracing/Monitoring log */
    events.perf_submit(ctx, &data, sizeof(data));

    if(CONDITIONS) {
        return ACTION;
    }
    return INVERSE;
}