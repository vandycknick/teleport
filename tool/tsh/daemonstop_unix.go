//go:build !windows
// +build !windows

package main

// onDaemonStop implements the "tsh daemon stop" command. It handles graceful shutdown of the daemon
// on Windows, so it's a noop on other platforms. See daemonstop_windows.go for more details.
func onDaemonStop(cf *CLIConf) error {
	return nil
}
