//go:build linux
// +build linux

package main

import "syscall"

func redirectStdin(fd int) error {
	return syscall.Dup3(fd, 0, 0)
}
