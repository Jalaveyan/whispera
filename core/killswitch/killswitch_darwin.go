package killswitch

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
)

const (
	pfConfPath = "/tmp/whispera_killswitch.conf"
	anchorName = "whispera_killswitch"
)

type DarwinKillSwitch struct {
	mu          sync.Mutex
	rulesActive bool
}

func NewPlatformImpl() (Platform, error) {
	return &DarwinKillSwitch{}, nil
}
func (d *DarwinKillSwitch) Name() string {
	return "darwin"
}

func (d *DarwinKillSwitch) IsSupported() bool {
	cmd := exec.Command("pfctl", "-s", "info")
	err := cmd.Run()
	return err == nil
}

func (d *DarwinKillSwitch) Enable(vpnServerIP net.IP, vpnPort int, allowLAN, allowDNS bool, allowedIPs []net.IP) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	var rules strings.Builder
	rules.WriteString("pass quick on lo0 all\n")
	vpnIP := vpnServerIP.String()
	rules.WriteString(fmt.Sprintf("pass out quick to %s\n", vpnIP))
	rules.WriteString(fmt.Sprintf("pass in quick from %s\n", vpnIP))
	if allowLAN {
		lanRanges := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"}
		for _, cidr := range lanRanges {
			rules.WriteString(fmt.Sprintf("pass quick to %s\n", cidr))
			rules.WriteString(fmt.Sprintf("pass quick from %s\n", cidr))
		}
	}
	if allowDNS {
		rules.WriteString("pass out quick proto udp to any port 53\n")
		rules.WriteString("pass out quick proto tcp to any port 53\n")
	}
	for _, ip := range allowedIPs {
		rules.WriteString(fmt.Sprintf("pass quick to %s\n", ip.String()))
		rules.WriteString(fmt.Sprintf("pass quick from %s\n", ip.String()))
	}
	rules.WriteString("pass quick on utun0 all\n")
	rules.WriteString("pass quick on utun1 all\n")
	rules.WriteString("pass quick on utun2 all\n")
	rules.WriteString("block drop all\n")
	if err := os.WriteFile(pfConfPath, []byte(rules.String()), 0600); err != nil {
		return fmt.Errorf("failed to write pf rules: %w", err)
	}
	if err := d.runPfctl("-a", anchorName, "-f", pfConfPath); err != nil {
		return fmt.Errorf("failed to load pf rules: %w", err)
	}
	d.runPfctl("-e")
	d.rulesActive = true
	return nil
}
func (d *DarwinKillSwitch) Disable() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.runPfctl("-a", anchorName, "-F", "all")
	os.Remove(pfConfPath)

	d.rulesActive = false
	return nil
}

func (d *DarwinKillSwitch) IsActive() (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.rulesActive, nil
}
func (d *DarwinKillSwitch) Cleanup() error {
	return d.Disable()
}
func (d *DarwinKillSwitch) runPfctl(args ...string) error {
	cmd := exec.Command("pfctl", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pfctl failed: %v, output: %s", err, string(output))
	}
	return nil
}
