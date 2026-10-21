//go:build linux || darwin

package coordinator

import "syscall"

func processCPUTimeNanos() int64 {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0
	}
	userNs := int64(ru.Utime.Sec)*1e9 + int64(ru.Utime.Usec)*1e3
	sysNs := int64(ru.Stime.Sec)*1e9 + int64(ru.Stime.Usec)*1e3
	return userNs + sysNs
}
