package utils

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
)

// Function to read process executable path
func GetExecutablePath(pid int32) string {
	path := fmt.Sprintf("/proc/%d/exe", pid)
	exePath, err := os.Readlink(path)
	if err != nil {
		return "unknown"
	}
	return exePath
}

// Function to read full command line
func GetCommandLine(pid int32) string {
	path := fmt.Sprintf("/proc/%d/cmdline", pid)
	data, err := os.ReadFile(path)
	if err != nil {
		return "unknown"
	}
	// Replace null characters with spaces to reconstruct the full command line
	return strings.ReplaceAll(string(data), "\x00", " ")
}

func GetUserFromID(uid int) string {
	usr, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return "unknown user"
	}
	return usr.Username
}
