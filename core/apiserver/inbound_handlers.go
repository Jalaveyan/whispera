package apiserver

import (
	"fmt"
	"os/exec"
)

// OpenFirewallPort opens the given port for both TCP and UDP via ufw.
// Used both from the HTTP inbound-management handlers and the create-key CLI.
func OpenFirewallPort(port int) error {
	if port <= 0 || port > 65535 {
		return fmt.Errorf("invalid port %d", port)
	}

	if _, err := exec.LookPath("ufw"); err != nil {
		return fmt.Errorf("ufw not found in PATH, skipping firewall config")
	}
	if out, err := runUFW("allow", fmt.Sprintf("%d/udp", port)); err != nil {
		return fmt.Errorf("failed to allow UDP: %v (output: %s)", err, string(out))
	}
	if out, err := runUFW("allow", fmt.Sprintf("%d/tcp", port)); err != nil {
		return fmt.Errorf("failed to allow TCP: %v (output: %s)", err, string(out))
	}

	return nil
}
