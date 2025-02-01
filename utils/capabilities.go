package utils

// List of Linux capabilities based on the capability bitmask
var capNames = map[uint64]string{
	1:        "CAP_CHOWN",
	2:        "CAP_DAC_OVERRIDE",
	4:        "CAP_DAC_READ_SEARCH",
	8:        "CAP_FOWNER",
	16:       "CAP_FSETID",
	32:       "CAP_KILL",
	64:       "CAP_SETGID",
	128:      "CAP_SETUID",
	256:      "CAP_SETPCAP",
	512:      "CAP_LINUX_IMMUTABLE",
	1024:     "CAP_NET_BIND_SERVICE",
	2048:     "CAP_NET_BROADCAST",
	4096:     "CAP_NET_ADMIN",
	8192:     "CAP_NET_RAW",
	16384:    "CAP_SYS_CHROOT",
	32768:    "CAP_SYS_PTRACE",
	65536:    "CAP_SYS_MODULE",
	131072:   "CAP_SYS_RAWIO",
	262144:   "CAP_SYS_PACCT",
	524288:   "CAP_SYS_ADMIN",
	1048576:  "CAP_SYS_BOOT",
	2097152:  "CAP_SYS_NICE",
	4194304:  "CAP_SYS_RESOURCE",
	8388608:  "CAP_SYS_TIME",
	16777216: "CAP_SYS_TTY_CONFIG",
	33554432: "CAP_MKNOD",
	67108864: "CAP_LEASE",
	134217728:"CAP_AUDIT_WRITE",
	268435456:"CAP_AUDIT_CONTROL",
	536870912:"CAP_SETFCAP",
	1073741824:"CAP_MAC_OVERRIDE",
	2147483648:"CAP_MAC_ADMIN",
	4294967296:"CAP_SYSLOG",
	8589934592:"CAP_WAKE_ALARM",
	17179869184:"CAP_BLOCK_SUSPEND",
	34359738368:"CAP_AUDIT_READ",
}

// Function to decode the capability bitmask
func DecodeCapabilities(mask uint64) []string {
	var capabilities []string

	// Iterate over the capNames map and check if each capability is set in the bitmask
	for bit, cap := range capNames {
		if mask&bit != 0 {
			capabilities = append(capabilities, cap)
		}
	}

	return capabilities
}