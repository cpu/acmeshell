// +build darwin freebsd

package main

import "syscall"

func redirectStdin(fd int) error {
	return syscall.Dup2(fd, 0)
}
