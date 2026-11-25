//go:build !darwin

package worker

func memTotal() int64 { return memTotalLinux() }
