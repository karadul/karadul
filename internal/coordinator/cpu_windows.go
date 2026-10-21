//go:build windows

package coordinator

import (
	"syscall"
	"unsafe"
)

func processCPUTimeNanos() int64 {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getProcessTimes := kernel32.NewProc("GetProcessTimes")
	var creationTime, exitTime, kernelTime, userTime syscall.Filetime
	handle, err := syscall.GetCurrentProcess()
	if err != nil {
		return 0
	}
	ret, _, _ := getProcessTimes.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&creationTime)),
		uintptr(unsafe.Pointer(&exitTime)),
		uintptr(unsafe.Pointer(&kernelTime)),
		uintptr(unsafe.Pointer(&userTime)),
	)
	if ret == 0 {
		return 0
	}
	kernelNs := (int64(kernelTime.HighDateTime) << 32) | int64(kernelTime.LowDateTime)
	userNs := (int64(userTime.HighDateTime) << 32) | int64(userTime.LowDateTime)
	return (kernelNs + userNs) * 100
}
