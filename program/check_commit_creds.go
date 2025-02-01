package program

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	devstdout "github.com/containerscrew/devstdout/pkg"
	"os"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type event -tags linux bpf check_commit_creds.bpf.c -- -I../headers

// Function to read process executable path
func getExecutablePath(pid int32) string {
	path := fmt.Sprintf("/proc/%d/exe", pid)
	exePath, err := os.Readlink(path)
	if err != nil {
		return "unknown"
	}
	return exePath
}

// Function to read full command line
func getCommandLine(pid int32) string {
	path := fmt.Sprintf("/proc/%d/cmdline", pid)
	data, err := os.ReadFile(path)
	if err != nil {
		return "unknown"
	}
	// Replace null characters with spaces to reconstruct the full command line
	return strings.ReplaceAll(string(data), "\x00", " ")
}

func GetCommitCreds(log *devstdout.CustomLogger) {
	// Name of the kernel function to trace.
	fn := "commit_creds"

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Error(fmt.Sprintf("failed to remove memlock rlimit: %v. Consider using sudo or give necessary capabilities to the program", err))
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Error(fmt.Sprintf("loading objects: %v", err))
	}
	defer objs.Close()

	kp, err := link.Kprobe(fn, objs.CommitCreds, nil)
	if err != nil {
		log.Error(fmt.Sprintf("failed to open kprobe: %v", err))
	}
	defer kp.Close()

	rd, err := ringbuf.NewReader(objs.bpfMaps.Events)
	if err != nil {
		log.Error(fmt.Sprintf("failed to create ring buffer reader: %v", err))
	}
	defer rd.Close()

	var event bpfEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Warning("received signal, closing ringbuf reader..")
				return
			}
			log.Error("reading from reader: %s\n", err)
			continue
		}

		// Parse the ringbuf event entry into a bpfEvent structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Warning("parsing ringbuf event: %s", err)
			continue
		}

		// Fetch additional process details
		exePath := getExecutablePath(event.Tgid)
		cmdLine := getCommandLine(event.Tgid)

		if cmdLine != "" {
			log.Info("Root privilege escalation detected",
				devstdout.Argument("pid", event.Tgid),
				devstdout.Argument("exe_path", exePath),
				devstdout.Argument("cmd_line", cmdLine),
				devstdout.Argument("old_uid", event.OldUid),
				devstdout.Argument("new_uid", event.NewUid),
			)
		}
	}
}
