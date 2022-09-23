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

    u32 mmap_base; /* base of mmap area*/
    u32 mmap_legacy_base; /* base of mmap area in bottom-up allocations */
    u32 task_size; /* size of task vm space*/
    u32 highest_vm_end; /* highest vma end address */
    u32 vm_start;
    u32 vm_end;
    u32 total_vm; /* Total pages mapped */

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
 * Attach to the "vm_enough_memory" LSM hook
 */
// vm_enough_memory_mm hook returns __vm_enough_memory function (in /mm/util.c)
LSM_PROBE(vm_enough_memory, struct mm_struct *mm, long pages) {
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

    data.mmap_base = mm->mmap_base;
    data.mmap_legacy_base = mm->mmap_legacy_base;
    data.task_size = mm->task_size;
    data.highest_vm_end = mm-> highest_vm_end;

    data.vm_start = mm->mmap->vm_start;
    data.vm_end = mm->mmap->vm_end;

    data.total_vm = mm->total_vm;

    /* Tracing/Monitoring log */
    events.perf_submit(ctx, &data, sizeof(data));

    if(CONDITIONS) {
        return ACTION;
    }
    return INVERSE;
}