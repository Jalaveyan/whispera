//go:build linux

// Package killswitch provides Linux implementation using iptables
package killswitch

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
)

const (
	chainName = "WHISPERA_KILLSWITCH"
)

// LinuxKillSwitch implements kill switch using iptables
type LinuxKillSwitch struct {
	mu          sync.Mutex
	rulesActive bool
	savedRules  string // Original iptables rules for restoration
}

// NewPlatformImpl creates Linux-specific implementation
func NewPlatformImpl() (Platform, error) {
	return &LinuxKillSwitch{}, nil
}

// Name returns platform name
func (l *LinuxKillSwitch) Name() string {
	return "linux"
}

// IsSupported checks if iptables is available
func (l *LinuxKillSwitch) IsSupported() bool {
	// Check if iptables is available and we have root privileges
	cmd := exec.Command("iptables", "-L", "-n")
	err := cmd.Run()
	return err == nil
}

// Enable activates kill switch rules
func (l *LinuxKillSwitch) Enable(vpnServerIP net.IP, vpnPort int, allowLAN, allowDNS bool, allowedIPs []net.IP) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Save current rules for potential restoration
	if err := l.saveCurrentRules(); err != nil {
		log.Warn("Failed to save current iptables rules: %v", err)
	}

	// Create our custom chain
	if err := l.createChain(); err != nil {
		return fmt.Errorf("failed to create chain: %w", err)
	}

	// Flush our chain first
	l.runIPTables("-F", chainName)

	// 1. Allow loopback interface
	if err := l.runIPTables("-A", chainName, "-i", "lo", "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("failed to allow loopback: %w", err)
	}
	if err := l.runIPTables("-A", chainName, "-o", "lo", "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("failed to allow loopback output: %w", err)
	}

	// 2. Allow established connections
	if err := l.runIPTables("-A", chainName, "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("failed to allow established: %w", err)
	}

	// 3. Allow VPN server
	vpnIP := vpnServerIP.String()
	if err := l.runIPTables("-A", chainName, "-d", vpnIP, "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("failed to allow VPN outbound: %w", err)
	}
	if err := l.runIPTables("-A", chainName, "-s", vpnIP, "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("failed to allow VPN inbound: %w", err)
	}

	// 4. Allow LAN if enabled
	if allowLAN {
		lanRanges := []string{
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
			"169.254.0.0/16", // Link-local
		}
		for _, cidr := range lanRanges {
			if err := l.runIPTables("-A", chainName, "-d", cidr, "-j", "ACCEPT"); err != nil {
				log.Warn("Failed to add LAN rule for %s: %v", cidr, err)
			}
			if err := l.runIPTables("-A", chainName, "-s", cidr, "-j", "ACCEPT"); err != nil {
				log.Warn("Failed to add LAN rule for %s: %v", cidr, err)
			}
		}
	}

	// 5. Allow DNS if enabled
	if allowDNS {
		if err := l.runIPTables("-A", chainName, "-p", "udp", "--dport", "53", "-j", "ACCEPT"); err != nil {
			log.Warn("Failed to add DNS UDP rule: %v", err)
		}
		if err := l.runIPTables("-A", chainName, "-p", "tcp", "--dport", "53", "-j", "ACCEPT"); err != nil {
			log.Warn("Failed to add DNS TCP rule: %v", err)
		}
	}

	// 6. Allow additional IPs from config
	for _, ip := range allowedIPs {
		ipStr := ip.String()
		if err := l.runIPTables("-A", chainName, "-d", ipStr, "-j", "ACCEPT"); err != nil {
			log.Warn("Failed to add custom IP rule %s: %v", ipStr, err)
		}
		if err := l.runIPTables("-A", chainName, "-s", ipStr, "-j", "ACCEPT"); err != nil {
			log.Warn("Failed to add custom IP rule %s: %v", ipStr, err)
		}
	}

	// 7. Allow TUN/TAP interface traffic (VPN tunnel)
	tunInterfaces := []string{"tun0", "tun1", "tap0", "tap1", "wg0", "wg1"}
	for _, iface := range tunInterfaces {
		// Ignore errors for interfaces that don't exist
		l.runIPTables("-A", chainName, "-i", iface, "-j", "ACCEPT")
		l.runIPTables("-A", chainName, "-o", iface, "-j", "ACCEPT")
	}

	// 8. Block all other traffic (default DROP)
	if err := l.runIPTables("-A", chainName, "-j", "DROP"); err != nil {
		return fmt.Errorf("failed to add drop rule: %w", err)
	}

	// 9. Insert our chain into INPUT and OUTPUT
	if err := l.runIPTables("-I", "INPUT", "1", "-j", chainName); err != nil {
		return fmt.Errorf("failed to insert INPUT rule: %w", err)
	}
	if err := l.runIPTables("-I", "OUTPUT", "1", "-j", chainName); err != nil {
		return fmt.Errorf("failed to insert OUTPUT rule: %w", err)
	}
	if err := l.runIPTables("-I", "FORWARD", "1", "-j", chainName); err != nil {
		log.Warn("Failed to insert FORWARD rule: %v", err)
	}

	l.rulesActive = true
	log.Info("Linux iptables kill switch rules activated")
	return nil
}

// Disable removes kill switch rules
func (l *LinuxKillSwitch) Disable() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Remove references to our chain from main chains
	l.runIPTables("-D", "INPUT", "-j", chainName)
	l.runIPTables("-D", "OUTPUT", "-j", chainName)
	l.runIPTables("-D", "FORWARD", "-j", chainName)

	// Flush and delete our chain
	l.runIPTables("-F", chainName)
	l.runIPTables("-X", chainName)

	l.rulesActive = false
	log.Info("Linux iptables kill switch rules removed")

	// Restore original rules if we have them
	if err := l.restoreRules(); err != nil {
		log.Warn("Failed to restore original iptables rules: %v", err)
	}

	return nil
}

// IsActive returns true if rules are active
func (l *LinuxKillSwitch) IsActive() (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.rulesActive, nil
}

// Cleanup removes all kill switch rules
func (l *LinuxKillSwitch) Cleanup() error {
	return l.Disable()
}

// runIPTables executes an iptables command
func (l *LinuxKillSwitch) runIPTables(args ...string) error {
	cmd := exec.Command("iptables", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables %s failed: %v, output: %s", strings.Join(args, " "), err, string(output))
	}
	return nil
}

// createChain creates our custom iptables chain
func (l *LinuxKillSwitch) createChain() error {
	// Check if chain exists
	cmd := exec.Command("iptables", "-L", chainName, "-n")
	if err := cmd.Run(); err != nil {
		// Chain doesn't exist, create it
		if err := l.runIPTables("-N", chainName); err != nil {
			return err
		}
	}
	return nil
}

// saveCurrentRules saves current iptables rules for potential restoration
func (l *LinuxKillSwitch) saveCurrentRules() error {
	cmd := exec.Command("iptables-save")
	output, err := cmd.Output()
	if err != nil {
		return err
	}
	l.savedRules = string(output)
	return nil
}

// restoreRules restores previously saved rules
func (l *LinuxKillSwitch) restoreRules() error {
	if l.savedRules == "" {
		return nil
	}

	cmd := exec.Command("iptables-restore")
	cmd.Stdin = strings.NewReader(l.savedRules)
	return cmd.Run()
}
