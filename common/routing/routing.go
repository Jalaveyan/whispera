package routing

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

type RuleType string

const (
	RuleTypeDomain        RuleType = "domain"
	RuleTypeDomainSuffix  RuleType = "domain-suffix"
	RuleTypeDomainKeyword RuleType = "domain-keyword"
	RuleTypeDomainRegex   RuleType = "domain-regex"
	RuleTypeIP            RuleType = "ip"
	RuleTypeGeoIP         RuleType = "geoip"
	RuleTypeGeoSite       RuleType = "geosite"
	RuleTypePort          RuleType = "port"
	RuleTypeFinal         RuleType = "final"
)

type Action string

const (
	ActionDirect Action = "direct"
	ActionProxy  Action = "proxy"
	ActionReject Action = "reject"
)

type Rule struct {
	Type   RuleType
	Value  string
	Action Action
	Tag    string
	regex  *regexp.Regexp
}

type GeoIPDatabase struct {
	mu       sync.RWMutex
	ipRanges map[string][]*net.IPNet
	loaded   bool
}

type GeoSiteDatabase struct {
	mu       sync.RWMutex
	domains  map[string][]string
	suffixes map[string][]string
	keywords map[string][]string
	regexps  map[string][]*regexp.Regexp
	loaded   bool
}

type Router struct {
	rules   []Rule
	geoIP   *GeoIPDatabase
	geoSite *GeoSiteDatabase
	mu      sync.RWMutex

	matches uint64
	misses  uint64
}

func NewRouter() *Router {
	return &Router{
		rules: make([]Rule, 0),
		geoIP: &GeoIPDatabase{ipRanges: make(map[string][]*net.IPNet)},
		geoSite: &GeoSiteDatabase{
			domains:  make(map[string][]string),
			suffixes: make(map[string][]string),
			keywords: make(map[string][]string),
			regexps:  make(map[string][]*regexp.Regexp),
		},
	}
}

func (r *Router) AddRule(rule Rule) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if rule.Type == RuleTypeDomainRegex {
		re, err := regexp.Compile(rule.Value)
		if err != nil {
			return err
		}
		rule.regex = re
	}

	r.rules = append(r.rules, rule)
	return nil
}

func (r *Router) LoadGeoIPFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	r.geoIP.mu.Lock()
	defer r.geoIP.mu.Unlock()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ",", 2)
		if len(parts) != 2 {
			continue
		}

		code := strings.ToUpper(strings.TrimSpace(parts[0]))
		cidr := strings.TrimSpace(parts[1])

		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}

		r.geoIP.ipRanges[code] = append(r.geoIP.ipRanges[code], ipNet)
	}

	r.geoIP.loaded = true
	return scanner.Err()
}

func (r *Router) LoadGeoSiteFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	r.geoSite.mu.Lock()
	defer r.geoSite.mu.Unlock()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 2 {
			continue
		}

		category := strings.ToLower(parts[0])
		ruleType := "domain"
		value := parts[1]

		if len(parts) == 3 {
			ruleType = parts[1]
			value = parts[2]
		}

		switch ruleType {
		case "domain":
			r.geoSite.domains[category] = append(r.geoSite.domains[category], strings.ToLower(value))
		case "suffix":
			r.geoSite.suffixes[category] = append(r.geoSite.suffixes[category], strings.ToLower(value))
		case "keyword":
			r.geoSite.keywords[category] = append(r.geoSite.keywords[category], strings.ToLower(value))
		case "regexp":
			if re, err := regexp.Compile(value); err == nil {
				r.geoSite.regexps[category] = append(r.geoSite.regexps[category], re)
			}
		}
	}

	r.geoSite.loaded = true
	return scanner.Err()
}

func (r *Router) LoadGeoData(dir string) error {
	geoIPPath := filepath.Join(dir, "geoip.txt")
	geoSitePath := filepath.Join(dir, "geosite.txt")

	if _, err := os.Stat(geoIPPath); err == nil {
		if err := r.LoadGeoIPFile(geoIPPath); err != nil {
			return err
		}
	}

	if _, err := os.Stat(geoSitePath); err == nil {
		if err := r.LoadGeoSiteFile(geoSitePath); err != nil {
			return err
		}
	}

	return nil
}

func (r *Router) Match(destIP net.IP, destDomain string, destPort int) Action {
	r.mu.RLock()
	defer r.mu.RUnlock()

	domain := strings.ToLower(destDomain)

	for _, rule := range r.rules {
		matched := false

		switch rule.Type {
		case RuleTypeDomain:
			matched = domain == strings.ToLower(rule.Value)

		case RuleTypeDomainSuffix:
			suffix := strings.ToLower(rule.Value)
			matched = domain == suffix || strings.HasSuffix(domain, "."+suffix)

		case RuleTypeDomainKeyword:
			matched = strings.Contains(domain, strings.ToLower(rule.Value))

		case RuleTypeDomainRegex:
			if rule.regex != nil {
				matched = rule.regex.MatchString(domain)
			}

		case RuleTypeIP:
			if destIP != nil {
				_, ipNet, err := net.ParseCIDR(rule.Value)
				if err == nil {
					matched = ipNet.Contains(destIP)
				} else {
					ruleIP := net.ParseIP(rule.Value)
					matched = ruleIP != nil && ruleIP.Equal(destIP)
				}
			}

		case RuleTypeGeoIP:
			if destIP != nil {
				matched = r.matchGeoIP(destIP, rule.Value)
			}

		case RuleTypeGeoSite:
			matched = r.matchGeoSite(domain, rule.Value)

		case RuleTypePort:
			matched = r.matchPort(destPort, rule.Value)

		case RuleTypeFinal:
			matched = true
		}

		if matched {
			r.matches++
			return rule.Action
		}
	}

	r.misses++
	return ActionProxy
}

func (r *Router) matchGeoIP(ip net.IP, code string) bool {
	r.geoIP.mu.RLock()
	defer r.geoIP.mu.RUnlock()

	code = strings.ToUpper(code)
	ranges, ok := r.geoIP.ipRanges[code]
	if !ok {
		return false
	}

	for _, ipNet := range ranges {
		if ipNet.Contains(ip) {
			return true
		}
	}

	return false
}

func (r *Router) matchGeoSite(domain string, category string) bool {
	r.geoSite.mu.RLock()
	defer r.geoSite.mu.RUnlock()

	category = strings.ToLower(category)

	if domains, ok := r.geoSite.domains[category]; ok {
		for _, d := range domains {
			if domain == d {
				return true
			}
		}
	}

	if suffixes, ok := r.geoSite.suffixes[category]; ok {
		for _, s := range suffixes {
			if domain == s || strings.HasSuffix(domain, "."+s) {
				return true
			}
		}
	}

	if keywords, ok := r.geoSite.keywords[category]; ok {
		for _, k := range keywords {
			if strings.Contains(domain, k) {
				return true
			}
		}
	}

	if regexps, ok := r.geoSite.regexps[category]; ok {
		for _, re := range regexps {
			if re.MatchString(domain) {
				return true
			}
		}
	}

	return false
}

func (r *Router) matchPort(port int, value string) bool {
	if strings.Contains(value, "-") {
		parts := strings.SplitN(value, "-", 2)
		if len(parts) == 2 {
			var start, end int
			if _, err := parseIntFromString(parts[0], &start); err != nil {
				return false
			}
			if _, err := parseIntFromString(parts[1], &end); err != nil {
				return false
			}
			return port >= start && port <= end
		}
	}

	var rulePort int
	if _, err := parseIntFromString(value, &rulePort); err != nil {
		return false
	}
	return port == rulePort
}

func parseIntFromString(s string, result *int) (bool, error) {
	s = strings.TrimSpace(s)
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return false, nil
		}
		n = n*10 + int(c-'0')
	}
	*result = n
	return true, nil
}

func (r *Router) Stats() (matches, misses uint64) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.matches, r.misses
}

func (r *Router) GetCategories() []string {
	r.geoSite.mu.RLock()
	defer r.geoSite.mu.RUnlock()

	categories := make(map[string]bool)
	for k := range r.geoSite.domains {
		categories[k] = true
	}
	for k := range r.geoSite.suffixes {
		categories[k] = true
	}

	result := make([]string, 0, len(categories))
	for k := range categories {
		result = append(result, k)
	}
	return result
}

func (r *Router) GetCountries() []string {
	r.geoIP.mu.RLock()
	defer r.geoIP.mu.RUnlock()

	result := make([]string, 0, len(r.geoIP.ipRanges))
	for k := range r.geoIP.ipRanges {
		result = append(result, k)
	}
	return result
}
