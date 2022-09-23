/* ################################
 * Author: Songi Gwak
 * Date: 4/15/2022
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

    u32 inode;
    u32 oldmode;
    u32 newmode;

    u32 mntns;
};
struct str {
    char path[DNAME_INLINE_LEN];
    u32 len;
};

/*
 * Create a buffer for sending event data to userspace
 */
BPF_PERF_OUTPUT(events);

/* Functions */
BPF_HASH(fullpath, u32, struct str, 32);
static inline int read_dentry_path(const struct path *path, int* count){
    /* This function store path to a BPF_HASH map
    */
    struct dentry *lastdtryp;
    struct dentry *dcur;
    int full_length = 0;
    struct str test = {.len=0,.path={0}};
    // first entry
    dcur = path->dentry;
    test.len = bpf_probe_read_kernel_str(&test.path, DNAME_INLINE_LEN, dcur->d_name.name);
    full_length += test.len - 1;
    fullpath.update(count,&test);
    // NExt
    lastdtryp = dcur;
    dcur = dcur->d_parent;
    int i = 1;
    for (i = 1; i < DNAME_INLINE_LEN; i++) {
        if(lastdtryp!=dcur){
            test.len = bpf_probe_read_kernel_str(&test.path, DNAME_INLINE_LEN, dcur->d_name.name);
            full_length += test.len - 1;
            lastdtryp = dcur;
            dcur = dcur->d_parent;
            *count = i;
            fullpath.update((u32 *)count,&test);
        }
        else
            break;
    }
    *count = i-1;
    return full_length-2+i;
}

static inline bool equal_to_true(char *str, const char *comp, int start, int len) {
    char comparand[len];
    bpf_probe_read(&comparand, sizeof(comparand), str);
  
    for (int i = 0; i < len; ++i)
        if (comp[start+i] != comparand[i])
            return false;
    return true;
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
 * Attach to the "path_chmod" LSM hook
 */
LSM_PROBE(path_chmod, const struct path *path, umode_t mode) {
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

    /* data.inode container the affected path inode */
    data.inode = path->dentry->d_inode->i_ino;
    data.oldmode = (u32)path->dentry->d_inode->i_mode;
    data.newmode = (u32)mode;

    /* Tracing/Monitoring log */
    events.perf_submit(ctx, &data, sizeof(data));

    if(CONDITIONS) {
        return ACTION;
    }
    return INVERSE;
}