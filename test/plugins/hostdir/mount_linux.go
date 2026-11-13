package main

import "syscall"

func bind(src, dst string) error { return syscall.Mount(src, dst, "", syscall.MS_BIND, "") }

func unbind(path string) error { return syscall.Unmount(path, 0) }
