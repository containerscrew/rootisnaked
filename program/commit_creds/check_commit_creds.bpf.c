//go:build ignore

// Include necessary headers for eBPF programs and kernel structures
#include "../headers/vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <linux/version.h>

// Define the maximum path length (not used in this program but commonly included)
#define PATH_MAX 128

// Define the license and version for the eBPF program
char __license[] SEC("license") = "Dual MIT/GPL"; // Dual licensing for the eBPF program
__u32 __version SEC("version") = LINUX_VERSION_CODE; // Set the program version to the current Linux kernel version

// Define a structure to hold event data that will be sent to user space
struct event {
    pid_t tgid;       // Thread group ID (process ID) of the task
    u32 old_uid;      // Original UID before the change
    u32 new_uid;      // New UID after the change
    u64 old_caps;     // Old effective capabilities
    u64 new_caps;     // New effective capabilities
};

// Define a ring buffer map to pass events from kernel to user space
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF); // Use a ring buffer for efficient event streaming
    __uint(max_entries, 1 << 24);       // Set the maximum size of the ring buffer (16 MB)
} events SEC(".maps");

// Force the compiler to include the `event` structure in the ELF binary
const struct event *unused __attribute__((unused));

// Define the eBPF program that will be attached to the `commit_creds` kernel function
SEC("kprobe/commit_creds")
int commit_creds(struct pt_regs *regs)
{
    // Declare variables to hold task and credential information
    const struct task_struct *task; // Current task (process)
    const struct cred *old_cred, *new_cred; // Old and new credentials
    struct event *data; // Pointer to the event data structure
    kuid_t old_uid, new_uid; // Old and new UIDs
    u64 old_caps, new_caps; // Old and new effective capabilities

    // Get the new credentials from the first argument of `commit_creds`
    new_cred = (struct cred*)PT_REGS_PARM1(regs);
    if (!new_cred) // Check if new_cred is valid
        return 0;  // Exit if invalid

    // Get the current task (process) using a helper function
    task = (struct task_struct*)bpf_get_current_task();
    if (!task) // Check if task is valid
        return 0; // Exit if invalid

    // Read the old credentials from the current task
    if (bpf_core_read(&old_cred, sizeof(void *), &task->cred))
        return 0; // Exit if reading fails

    // Read the old and new UIDs from the credentials
    old_uid = BPF_CORE_READ(old_cred, uid); // Read old UID
    new_uid = BPF_CORE_READ(new_cred, uid); // Read new UID

    // Read the old and new effective capabilities
    old_caps = BPF_CORE_READ(old_cred, cap_effective.val);
    new_caps = BPF_CORE_READ(new_cred, cap_effective.val);

    // Check if the new UID is 0 (root) and the old UID was greater than 0 (non-root)
    // OR if the process gains new capabilities
    if ((new_uid.val == 0 && old_uid.val > 0) || (new_caps != old_caps)) {
        // Reserve space in the ring buffer for the event data
        data = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
        if (!data) {
            // If the ring buffer is full, log an error and exit
            bpf_printk("Error - ringbuffer is full\n");
            return 0;
        }

        // Fill the event data structure with relevant information
        data->tgid = BPF_CORE_READ(task, tgid); // Get the process ID
        data->old_uid = old_uid.val;            // Store the old UID
        data->new_uid = new_uid.val;            // Store the new UID
        data->old_caps = old_caps;              // Store the old capabilities
        data->new_caps = new_caps;              // Store the new capabilities

        // Submit the event to the ring buffer for user space to process
        bpf_ringbuf_submit(data, 0);
    }

    // Return 0 to indicate success
    return 0;
}
