/* ################################
 * Author: Songi Gwak
 * Date: 4/14/2022
 * Params: DATA_T_MORE_INFORMATION, 0xf00006d7, data.new_gid==100, -1
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

    // new cred
    u32 new_gid;
    /*
    u32 new_suid;
    u32 new_euid;
    u32 new_fsuid;
    */

    // old cred
    u32 old_gid;
    /*
    u32 old_suid;
    u32 old_euid;
    u32 old_fsuid;
    */

    u32 flags;
    u32 mntns;
};

/*
 * Values used in the task_security_ops calls
 */
/* setuid or setgid, id0 == uid or gid */
#define LSM_SETID_ID	1

/* setreuid or setregid, id0 == real, id1 == eff */
#define LSM_SETID_RE	2

/* setresuid or setresgid, id0 == real, id1 == eff, uid2 == saved */
#define LSM_SETID_RES	4

/* setfsuid or setfsgid, id0 == fsuid or fsgid */
#define LSM_SETID_FS	8

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
 * Attach to the "task_fix_setgid" LSM hook
 */
LSM_PROBE(task_fix_setgid, struct cred *new, const struct cred *old, int flags) {
    /*
    * Filter container first 
    */
    if(!container_should_be_filtered(0xf00006d7))
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

    data.new_gid = new->gid.val;
    data.old_gid = old->gid.val;
    data.flags = flags;

    /* Tracing/Monitoring log */
    events.perf_submit(ctx, &data, sizeof(data));

    if(data.new_gid==100) {
        return -1;
    }
    return 0;
}
