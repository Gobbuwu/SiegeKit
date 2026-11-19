//go:build linux || darwin

package main

import (
	"os"
	"syscall"
	"unsafe"
)

// isTerminal reports whether f is a terminal. A character device such as
// /dev/null is not: only a device that answers the terminal ioctl counts.
func isTerminal(f *os.File) bool {
	var t syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(ioctlGetTermios), uintptr(unsafe.Pointer(&t))) // #nosec G103 -- the termios ioctl needs a pointer to its result
	return errno == 0
}
