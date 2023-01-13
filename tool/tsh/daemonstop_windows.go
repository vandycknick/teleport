//go:build windows
// +build windows

package main

import (
	"syscall"

	"github.com/gravitational/trace"
	"golang.org/x/sys/windows"
)

func onDaemonStop(cf *CLIConf) error {
	k32, err := syscall.LoadDLL("kernel32.dll")
	if err != nil {
		return trace.Wrap(err)
	}

	freeConsole, err := k32.FindProc("FreeConsole")
	if err != nil {
		return trace.Wrap(err)
	}
	retVal, _, err := freeConsole.Call()
	if retVal == 0 {
		return trace.Wrap(err)
	}

	attachConsole, err := k32.FindProc("AttachConsole")
	if err != nil {
		return trace.Wrap(err)
	}
	retVal, _, err = attachConsole.Call(uintptr(cf.DaemonPid))
	if retVal == 0 {
		return trace.Wrap(err)
	}

	err = windows.GenerateConsoleCtrlEvent(windows.CTRL_C_EVENT, 0)
	return trace.Wrap(err)
}
