//go:build !linux

package main

import "errors"

var errLinux = errors.New("bind mounts need Linux")

func bind(string, string) error { return errLinux }

func unbind(string) error { return errLinux }
