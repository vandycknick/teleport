//go:build !windows
// +build !windows

package main

func onDaemonStop(cf *CLIConf) error {
	return nil
}
