package filepermissions

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	devstdout "github.com/containerscrew/devstdout/pkg"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event -tags linux bpf ./check_file_permissions.bpf.c -- -I../../headers

func formatMode(mode uint32) string {
	return fmt.Sprintf("%04o", mode&0o777) // Mask only the permission bits
}

func formatFilename(filename [256]int8) string {
	// Convert int8 array to byte slice
	byteSlice := make([]byte, len(filename))
	for i, b := range filename {
		byteSlice[i] = byte(b) // Cast int8 to byte
	}

	// Trim null bytes and return as string
	return string(bytes.Trim(byteSlice, "\x00"))
}

func FilePermissions(log *devstdout.CustomLogger) {
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

	// Link tracepoints
	tpEnterLink, err := link.Tracepoint("syscalls", "sys_enter_chmod", objs.FilePermissionsChmod, nil)
	if err != nil {
		log.Error(fmt.Sprintf("failed to open tracepoint: %v", err))
	}
	defer tpEnterLink.Close()

	tpFchmod, err := link.Tracepoint("syscalls", "sys_enter_fchmod", objs.FilePermissionsFchmod, nil)
	if err != nil {
		log.Error(fmt.Sprintf("failed to attach to sys_enter_fchmod: %v", err))
	}
	defer tpFchmod.Close()

	tpFchmodat, err := link.Tracepoint("syscalls", "sys_enter_fchmodat", objs.FilePermissionsFchmodat, nil)
	if err != nil {
		log.Error(fmt.Sprintf("failed to attach to sys_enter_fchmodat: %v", err))
	}
	defer tpFchmodat.Close()

	// tpChown, err := link.Tracepoint("syscalls", "sys_enter_chown", objs.FilePermissions, nil)
	// if err != nil {
	// 	log.Error(fmt.Sprintf("failed to attach to sys_enter_chown: %v", err))
	// }
	// defer tpChown.Close()

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
			log.Info("reading from reader: %s", err)
			continue
		}

		// Parse the ringbuf event entry into a bpfEvent structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Warning("parsing ringbuf event: %s", err)
			continue
		}

		comm := string(bytes.Trim(event.Comm[:], "\x00"))

		if comm == "nvidia-smi" {
			continue
		}

		log.Info("file permission changed",
			devstdout.Argument("command", comm),
			devstdout.Argument("pid", event.Pid),
			devstdout.Argument("uid", event.Uid),
			devstdout.Argument("file", formatFilename(event.Filename)),
			devstdout.Argument("mode", formatMode(event.Mode)),
		)
	}
}
