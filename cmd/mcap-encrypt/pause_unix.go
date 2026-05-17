//go:build !windows

package main

import (
	"os"
	"os/signal"
	"syscall"
)

func notifyPause(ch chan os.Signal) {
	signal.Notify(ch, syscall.SIGTSTP)
}

func resetPause(ch chan os.Signal) {
	signal.Stop(ch)
	signal.Reset(syscall.SIGTSTP)
}

func suspendSelf() {
	p, err := os.FindProcess(os.Getpid())
	if err == nil {
		_ = p.Signal(syscall.SIGSTOP)
	}
}
