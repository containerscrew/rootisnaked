//go:build ignore

#include "../headers/vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include <linux/version.h>

#define PATH_MAX 128

char __license[] SEC("license") = "Dual MIT/GPL";
__u32 __version SEC("version") = LINUX_VERSION_CODE;

struct event {
    pid_t tgid;
    u32 old_uid;
    u32 new_uid; 
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

SEC("kprobe/commit_creds")
int commit_creds(struct pt_regs *regs)
{
    const struct task_struct *task;
    const struct cred *old_cred, *new_cred;
    struct event *data;
    kuid_t old_uid, new_uid;
    
    new_cred = (struct cred*)PT_REGS_PARM1(regs);
    if (!new_cred)
        return 0;
    
    task = (struct task_struct*)bpf_get_current_task();
    if (!task)
        return 0;
    
    if (bpf_core_read(&old_cred, sizeof(void *), &task->cred)) 
        return 0;

    old_uid = BPF_CORE_READ(old_cred, uid);
    new_uid = BPF_CORE_READ(new_cred, uid);
  
    if (new_uid.val == 0 && old_uid.val > 0) {
        data = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
        if (!data) {
            bpf_printk("Error - ringbuffer is full\n");
            return 0;
        }

        // Fill the data structure
        data->tgid = BPF_CORE_READ(task, tgid);
        data->old_uid = old_uid.val;
        data->new_uid = new_uid.val;

        // Send the data to user space
        bpf_ringbuf_submit(data, 0);
    }

    return 0;
}