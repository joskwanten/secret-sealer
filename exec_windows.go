package main

import (
	"os/exec"
	"syscall"
)

// hideWindow stops oc/kubeseal from flashing a console window on Windows.
func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}
