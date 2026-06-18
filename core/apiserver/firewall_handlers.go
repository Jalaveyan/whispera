package apiserver

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

func ufwPath() string {
	for _, p := range []string{"/usr/sbin/ufw", "/sbin/ufw", "ufw"} {
		if path, err := exec.LookPath(p); err == nil {
			return path
		}
	}
	return "ufw"
}

func runUFW(args ...string) ([]byte, error) {
	ufw := ufwPath()
	out, err := exec.CommandContext(context.Background(), ufw, args...).CombinedOutput()
	if err == nil {
		return out, nil
	}
	outStr := string(out)
	if strings.Contains(outStr, "Read-only file system") {
		return out, fmt.Errorf("ufw unavailable: read-only filesystem (container environment)")
	}
	if sudo, serr := exec.LookPath("sudo"); serr == nil {
		out2, err2 := exec.CommandContext(context.Background(), sudo, append([]string{ufw}, args...)...).CombinedOutput()
		if err2 == nil {
			return out2, nil
		}
		if strings.Contains(string(out2), "Read-only file system") {
			return out2, fmt.Errorf("ufw unavailable: read-only filesystem (container environment)")
		}
		return out2, err2
	}
	return out, err
}
