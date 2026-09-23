package security

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

// CheckDebugger detects if a debugger is attached and exits if so.
// This makes it harder for attackers to step through the decryption process.
func CheckDebugger() error {
	if detectDebuggerEnv() {
		return fmt.Errorf("debugger detected: refusing to process sensitive data")
	}
	if runtime.GOOS == "linux" && detectPtrace() {
		return fmt.Errorf("debugger detected: refusing to process sensitive data")
	}
	return nil
}

// detectDebuggerEnv checks for common debugger environment variables
func detectDebuggerEnv() bool {
	debugVars := []string{
		"GODEBUG_ATTACH",
		"DLV_LISTEN",
		"GOFLAGS_DEBUG",
	}
	for _, v := range debugVars {
		if os.Getenv(v) != "" {
			return true
		}
	}
	// Check if running under delve
	for _, arg := range os.Args {
		if strings.Contains(arg, "dlv") || strings.Contains(arg, "debug") {
			return true
		}
	}
	return false
}

// detectPtrace checks /proc/self/status for TracerPid on Linux
func detectPtrace() bool {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "TracerPid:") {
			pid := strings.TrimSpace(strings.TrimPrefix(line, "TracerPid:"))
			if pid != "0" {
				return true
			}
		}
	}
	return false
}
