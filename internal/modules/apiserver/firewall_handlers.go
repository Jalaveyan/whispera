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

func ufwPath() string {
	for _, p := range []string{"/usr/sbin/ufw", "/sbin/ufw", "ufw"} {
		if path, err := exec.LookPath(p); err == nil {
			return path
		}
	}
	return "ufw"
}

func getFirewallStatus() (*FirewallStatus, error) {
	cmd := exec.Command(ufwPath(), "status", "numbered")
	out, err := cmd.CombinedOutput()
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

	out, err := exec.Command(ufwPath(), args...).CombinedOutput()
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
	cmd := exec.Command(ufwPath(), "--force", "delete", strconv.Itoa(req.Number))
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
		cmd = exec.Command(ufwPath(), "--force", "enable")
	} else {
		cmd = exec.Command(ufwPath(), "--force", "disable")
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "ufw error: "+strings.TrimSpace(string(out)))
		return
	}
	status, _ := getFirewallStatus()
	s.jsonOK(w, map[string]interface{}{"success": true, "message": strings.TrimSpace(string(out)), "status": status})
}
