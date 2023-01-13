//go:build windows
// +build windows

package main

import (
	"syscall"

	"github.com/gravitational/trace"
	"golang.org/x/sys/windows"
)

var (
	k32                   = syscall.NewLazyDLL("kernel32.dll")
	freeConsole           = k32.NewProc("FreeConsole")
	attachConsole         = k32.NewProc("AttachConsole")
)

func onDaemonStop(cf *CLIConf) error {
	retVal, _, err := freeConsole.Call()
	if retVal == 0 {
		return trace.Wrap(err)
	}

	retVal, _, err = attachConsole.Call(uintptr(cf.DaemonPid))
	if retVal == 0 {
		return trace.Wrap(err)
	}

	err = windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, 0)
	return trace.Wrap(err)
}
