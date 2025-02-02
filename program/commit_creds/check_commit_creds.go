package commitcreds

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	devstdout "github.com/containerscrew/devstdout/pkg"
	"github.com/containerscrew/rootisnaked/utils"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type event -tags linux bpf check_commit_creds.bpf.c -- -I../../headers

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
		exePath := utils.GetExecutablePath(event.Tgid)
		cmdLine := utils.GetCommandLine(event.Tgid)

		// Log the event.

		log.Info("uid changed or capabilities changed for process",
			devstdout.Argument("pid", event.Tgid),
			devstdout.Argument("exe_path", exePath),
			devstdout.Argument("cmd_line", cmdLine),
			devstdout.Argument("user", utils.GetUserFromID(int(event.OldUid))),
			devstdout.Argument("old_uid", event.OldUid),
			devstdout.Argument("new_uid", event.NewUid),
			devstdout.Argument("old_caps", utils.DecodeCapabilities(event.OldCaps)),
			devstdout.Argument("new_caps", utils.DecodeCapabilities(event.NewCaps)),
		)

	}
}
