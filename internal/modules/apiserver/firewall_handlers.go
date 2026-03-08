package apiserver

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

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

func getFirewallStatus() (*FirewallStatus, error) {
	cmd := exec.Command("ufw", "status", "numbered")
	out, err := cmd.Output()
	if err != nil {
		return &FirewallStatus{Active: false, Rules: []FirewallRule{}}, nil
	}

	status := &FirewallStatus{Rules: []FirewallRule{}}
	scanner := bufio.NewScanner(strings.NewReader(string(out)))

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
		s.jsonError(w, http.StatusInternalServerError, "Failed to get firewall status")
		return
	}
	s.jsonOK(w, status)
}

func (s *Server) handleFirewallAddRule(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action string `json:"action"` // "allow" or "deny"
		Port   string `json:"port"`   // e.g. "80" or "8080:8090"
		Proto  string `json:"proto"`  // "tcp", "udp", "any"
		From   string `json:"from"`   // "" means Anywhere
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid request")
		return
	}
	if req.Port == "" {
		s.jsonError(w, http.StatusBadRequest, "port required")
		return
	}
	action := "allow"
	if req.Action == "deny" {
		action = "deny"
	}

	var rule string
	if req.From != "" {
		if req.Proto != "" && req.Proto != "any" {
			rule = fmt.Sprintf("from %s to any port %s proto %s", req.From, req.Port, req.Proto)
		} else {
			rule = fmt.Sprintf("from %s to any port %s", req.From, req.Port)
		}
	} else {
		if req.Proto != "" && req.Proto != "any" {
			rule = fmt.Sprintf("%s/%s", req.Port, req.Proto)
		} else {
			rule = req.Port
		}
	}

	args := []string{action}
	if req.From != "" {
		args = append(args, strings.Fields(rule)...)
	} else {
		args = append(args, rule)
	}

	out, err := exec.Command("ufw", args...).CombinedOutput()
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
	// ufw delete requires answering 'y' — use echo to confirm
	cmd := exec.Command("ufw", "--force", "delete", strconv.Itoa(req.Number))
	out, err := cmd.CombinedOutput()
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
	var cmd *exec.Cmd
	if req.Enable {
		cmd = exec.Command("ufw", "--force", "enable")
	} else {
		cmd = exec.Command("ufw", "--force", "disable")
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "ufw error: "+strings.TrimSpace(string(out)))
		return
	}
	status, _ := getFirewallStatus()
	s.jsonOK(w, map[string]interface{}{"success": true, "message": strings.TrimSpace(string(out)), "status": status})
}
