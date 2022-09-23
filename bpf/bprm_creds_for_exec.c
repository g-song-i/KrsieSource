/* ################################
 * Author: Songi Gwak
 * Date: 4/19/2022
 * Params: DATA_T_MORE_INFORMATION, MOUNT_NS_ID, CONDITIONS, ACTION
 * ################################
 */

#include <linux/security.h>
#include <linux/nsproxy.h>
#include <linux/mount.h>
#include <linux/ns_common.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h> 
#include <linux/binfmts.h>

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

    // for binprm 
    u32 fd;
    u32 inode;
    u32 argc;
    u32 envc;

    // for cred of new execve process
    u32 new_cred_uid;
    u32 new_cred_gid;
    u32 new_cred_euid;
    u32 new_cred_egid;
    u32 new_cred_suid;
    u32 new_cred_sgid;

    u32 mntns;
};

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
 * Attach to the "bprm_creds_for_exec" LSM hook
 */
// bprm_check internally calls ima_bprm_check, which is based on policy, collect/store measurement
// int ima_bprm_check(struct linux_binprm *bprm) return 0, if it's success or it returns -EACCES. this first gets current secid by using security_task_getsecid. and check this process by using process_measurement. as understanding, this first checking is for current cred. second, they gets the secid of bprm's cred by using security_cred_getsecid, and then check this cred by using process_measurement
// linux_binprm structure is used to hold the arguments that are used when loading binaries
// an explanation of linux_binprm is shown here: https://elixir.bootlin.com/linux/v5.12.11/source/include/linux/binfmts.h#L17
LSM_PROBE(bprm_creds_for_exec, struct linux_binprm *bprm) {
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

    data.fd = bprm->execfd;
    data.inode = bprm->executable->f_inode->i_ino;
    data.argc = bprm->argc;
    data.envc = bprm->envc;

    data.new_cred_uid = bprm->cred->uid.val;
    data.new_cred_gid = bprm->cred->gid.val;
    data.new_cred_euid = bprm->cred->euid.val;
    data.new_cred_egid = bprm->cred->egid.val;
    data.new_cred_suid = bprm->cred->suid.val;
    data.new_cred_sgid = bprm->cred->sgid.val;

    /* Tracing/Monitoring log */
    events.perf_submit(ctx, &data, sizeof(data));

    if(CONDITIONS) {
        return ACTION;
    }
    return INVERSE;
}