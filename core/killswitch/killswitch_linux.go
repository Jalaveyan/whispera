package killswitch

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
)

const (
	chainName = "WHISPERA_KILLSWITCH"
)

type LinuxKillSwitch struct {
	mu          sync.Mutex
	rulesActive bool
	savedRules  string
}

func NewPlatformImpl() (Platform, error) {
	return &LinuxKillSwitch{}, nil
}
func (l *LinuxKillSwitch) Name() string {
	return "linux"
}

func (l *LinuxKillSwitch) IsSupported() bool {
	cmd := exec.CommandContext(context.Background(), "iptables", "-L", "-n")
	err := cmd.Run()
	return err == nil
}

func (l *LinuxKillSwitch) Enable(vpnServerIP net.IP, vpnPort int, allowLAN, allowDNS bool, allowedIPs []net.IP) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.saveCurrentRules(); err != nil {
	}
	if err := l.createChain(); err != nil {
		return fmt.Errorf("failed to create chain: %w", err)
	}
	_ = l.runIPTables("-F", chainName)
	if err := l.runIPTables("-A", chainName, "-i", "lo", "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("failed to allow loopback: %w", err)
	}
	if err := l.runIPTables("-A", chainName, "-o", "lo", "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("failed to allow loopback output: %w", err)
	}
	if err := l.runIPTables("-A", chainName, "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("failed to allow established: %w", err)
	}
	vpnIP := vpnServerIP.String()
	if err := l.runIPTables("-A", chainName, "-d", vpnIP, "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("failed to allow VPN outbound: %w", err)
	}
	if err := l.runIPTables("-A", chainName, "-s", vpnIP, "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("failed to allow VPN inbound: %w", err)
	}
	if allowLAN {
		lanRanges := []string{
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
			"169.254.0.0/16",
		}
		for _, cidr := range lanRanges {
			if err := l.runIPTables("-A", chainName, "-d", cidr, "-j", "ACCEPT"); err != nil {
			}
			if err := l.runIPTables("-A", chainName, "-s", cidr, "-j", "ACCEPT"); err != nil {
			}
		}
	}
	if allowDNS {
		if err := l.runIPTables("-A", chainName, "-p", "udp", "--dport", "53", "-j", "ACCEPT"); err != nil {
		}
		if err := l.runIPTables("-A", chainName, "-p", "tcp", "--dport", "53", "-j", "ACCEPT"); err != nil {
		}
	}
	for _, ip := range allowedIPs {
		ipStr := ip.String()
		if err := l.runIPTables("-A", chainName, "-d", ipStr, "-j", "ACCEPT"); err != nil {
		}
		if err := l.runIPTables("-A", chainName, "-s", ipStr, "-j", "ACCEPT"); err != nil {
		}
	}
	tunInterfaces := []string{"tun0", "tun1", "tap0", "tap1", "wg0", "wg1"}
	for _, iface := range tunInterfaces {
		_ = l.runIPTables("-A", chainName, "-i", iface, "-j", "ACCEPT")
		_ = l.runIPTables("-A", chainName, "-o", iface, "-j", "ACCEPT")
	}
	if err := l.runIPTables("-A", chainName, "-j", "DROP"); err != nil {
		return fmt.Errorf("failed to add drop rule: %w", err)
	}
	if err := l.runIPTables("-I", "INPUT", "1", "-j", chainName); err != nil {
		return fmt.Errorf("failed to insert INPUT rule: %w", err)
	}
	if err := l.runIPTables("-I", "OUTPUT", "1", "-j", chainName); err != nil {
		return fmt.Errorf("failed to insert OUTPUT rule: %w", err)
	}
	if err := l.runIPTables("-I", "FORWARD", "1", "-j", chainName); err != nil {
	}

	l.rulesActive = true
	return nil
}

func (l *LinuxKillSwitch) Disable() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = l.runIPTables("-D", "INPUT", "-j", chainName)
	_ = l.runIPTables("-D", "OUTPUT", "-j", chainName)
	_ = l.runIPTables("-D", "FORWARD", "-j", chainName)
	_ = l.runIPTables("-F", chainName)
	_ = l.runIPTables("-X", chainName)

	l.rulesActive = false
	if err := l.restoreRules(); err != nil {
	}

	return nil
}
func (l *LinuxKillSwitch) IsActive() (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.rulesActive, nil
}
func (l *LinuxKillSwitch) Cleanup() error {
	return l.Disable()
}
func (l *LinuxKillSwitch) runIPTables(args ...string) error {
	cmd := exec.CommandContext(context.Background(), "iptables", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables %s failed: %v, output: %s", strings.Join(args, " "), err, string(output))
	}
	return nil
}

func (l *LinuxKillSwitch) createChain() error {
	cmd := exec.CommandContext(context.Background(), "iptables", "-L", chainName, "-n")
	if err := cmd.Run(); err != nil {
		if err := l.runIPTables("-N", chainName); err != nil {
			return err
		}
	}
	return nil
}
func (l *LinuxKillSwitch) saveCurrentRules() error {
	cmd := exec.CommandContext(context.Background(), "iptables-save")
	output, err := cmd.Output()
	if err != nil {
		return err
	}
	l.savedRules = string(output)
	return nil
}
func (l *LinuxKillSwitch) restoreRules() error {
	if l.savedRules == "" {
		return nil
	}

	cmd := exec.CommandContext(context.Background(), "iptables-restore")
	cmd.Stdin = strings.NewReader(l.savedRules)
	return cmd.Run()
}
