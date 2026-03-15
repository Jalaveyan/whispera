package apiserver

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

func isValidPort(p string) bool {
	if strings.Contains(p, ":") {
		parts := strings.SplitN(p, ":", 2)
		if len(parts) != 2 {
			return false
		}
		return isValidPortNum(parts[0]) && isValidPortNum(parts[1])
	}
	return isValidPortNum(p)
}

func isValidPortNum(s string) bool {
	n, err := strconv.Atoi(s)
	return err == nil && n >= 1 && n <= 65535
}

var _ = net.ParseIP

type FirewallRule struct {
	Number    int    `json:"number"`
	To        string `json:"to"`
	Action    string `json:"action"`
	From      string `json:"from"`
	IPv6      bool   `json:"ipv6"`
}

type FirewallStatus struct {
	Active bool           `json:"active"`
	Rules  []FirewallRule `json:"rules"`
}

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
	// Try directly first — works when process has CAP_NET_ADMIN (AmbientCapabilities in systemd unit).
	// sudo is blocked when NoNewPrivileges=true is set in the service.
	out, err := exec.CommandContext(context.Background(), ufw, args...).CombinedOutput()
	if err == nil {
		return out, nil
	}
	// Fall back to sudo for setups without ambient capabilities.
	if sudo, serr := exec.LookPath("sudo"); serr == nil {
		return exec.CommandContext(context.Background(), sudo, append([]string{ufw}, args...)...).CombinedOutput()
	}
	return out, err
}

func getFirewallStatus() (*FirewallStatus, error) {
	out, err := runUFW("status", "numbered")
	outStr := string(out)
	if err != nil && !strings.Contains(outStr, "Status:") {
		return &FirewallStatus{Active: false, Rules: []FirewallRule{}}, fmt.Errorf("ufw: %s", strings.TrimSpace(outStr))
	}

	status := &FirewallStatus{Rules: []FirewallRule{}}
	scanner := bufio.NewScanner(strings.NewReader(outStr))

	ruleRe := regexp.MustCompile(`^\[\s*(\d+)\]\s+(.+?)\s{2,}(ALLOW IN|DENY IN|ALLOW OUT|DENY OUT|ALLOW|DENY|REJECT|LIMIT)\s+(.+)$`)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Status: active") {
			status.Active = true
			continue
		}
		m := ruleRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		num, _ := strconv.Atoi(strings.TrimSpace(m[1]))
		to := strings.TrimSpace(m[2])
		action := strings.TrimSpace(m[3])
		from := strings.TrimSpace(m[4])
		ipv6 := strings.Contains(to, "(v6)") || strings.Contains(from, "(v6)")
		to = strings.TrimSuffix(strings.TrimSpace(strings.TrimSuffix(to, "(v6)")), " ")
		from = strings.TrimSuffix(strings.TrimSpace(strings.TrimSuffix(from, "(v6)")), " ")
		status.Rules = append(status.Rules, FirewallRule{
			Number: num,
			To:     to,
			Action: action,
			From:   from,
			IPv6:   ipv6,
		})
	}
	return status, nil
}

func (s *Server) handleFirewallStatus(w http.ResponseWriter, r *http.Request) {
	status, err := getFirewallStatus()
	if err != nil {
		s.jsonOK(w, map[string]interface{}{
			"active": false,
			"rules":  []FirewallRule{},
			"error":  err.Error(),
		})
		return
	}
	s.jsonOK(w, status)
}

func (s *Server) handleFirewallAddRule(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action string `json:"action"`
		Port   string `json:"port"`
		Proto  string `json:"proto"`
		From   string `json:"from"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid request")
		return
	}
	if req.Port == "" {
		s.jsonError(w, http.StatusBadRequest, "port required")
		return
	}
	if !isValidPort(req.Port) {
		s.jsonError(w, http.StatusBadRequest, "invalid port")
		return
	}
	if req.From != "" && net.ParseIP(req.From) == nil {
		_, _, err := net.ParseCIDR(req.From)
		if err != nil {
			s.jsonError(w, http.StatusBadRequest, "invalid IP address")
			return
		}
	}
	if req.Proto != "" && req.Proto != "any" && req.Proto != "tcp" && req.Proto != "udp" {
		s.jsonError(w, http.StatusBadRequest, "invalid protocol, must be tcp/udp/any")
		return
	}

	action := "allow"
	if req.Action == "deny" {
		action = "deny"
	}

	var args []string
	if req.From != "" {
		args = []string{action, "from", req.From, "to", "any", "port", req.Port}
		if req.Proto != "" && req.Proto != "any" {
			args = append(args, "proto", req.Proto)
		}
	} else {
		if req.Proto != "" && req.Proto != "any" {
			args = []string{action, req.Port + "/" + req.Proto}
		} else {
			args = []string{action, req.Port}
		}
	}

	out, err := runUFW(args...)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "ufw error: "+strings.TrimSpace(string(out)))
		return
	}
	status, _ := getFirewallStatus()
	s.jsonOK(w, map[string]interface{}{"success": true, "message": strings.TrimSpace(string(out)), "status": status})
}

func (s *Server) handleFirewallDeleteRule(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Number int `json:"number"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Number <= 0 {
		s.jsonError(w, http.StatusBadRequest, "rule number required")
		return
	}
	out, err := runUFW("--force", "delete", strconv.Itoa(req.Number))
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "ufw error: "+strings.TrimSpace(string(out)))
		return
	}
	status, _ := getFirewallStatus()
	s.jsonOK(w, map[string]interface{}{"success": true, "message": strings.TrimSpace(string(out)), "status": status})
}

func (s *Server) handleFirewallToggle(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enable bool `json:"enable"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid request")
		return
	}
	var args []string
	if req.Enable {
		args = []string{"--force", "enable"}
	} else {
		args = []string{"--force", "disable"}
	}
	out, err := runUFW(args...)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "ufw error: "+strings.TrimSpace(string(out)))
		return
	}
	status, _ := getFirewallStatus()
	s.jsonOK(w, map[string]interface{}{"success": true, "message": strings.TrimSpace(string(out)), "status": status})
}
