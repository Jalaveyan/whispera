package wiraid

import (
	"strconv"
	"strings"
)

type RenderContext struct {
	Binary       string
	ModuleDir    string
	ConfigPath   string
	ListenHost   string
	ListenPort   int
	UpstreamHost string
	UpstreamPort int
	ServerHost   string
	Params       map[string]string
}

func (c *RenderContext) lookup(key string) (string, bool) {
	switch key {
	case "binary":
		return c.Binary, true
	case "module_dir":
		return c.ModuleDir, true
	case "config_path":
		return c.ConfigPath, true
	case "listen_host":
		return c.ListenHost, true
	case "listen_port":
		return strconv.Itoa(c.ListenPort), true
	case "upstream_host":
		return c.UpstreamHost, true
	case "upstream_port":
		if c.UpstreamPort == 0 {
			return "", true
		}
		return strconv.Itoa(c.UpstreamPort), true
	case "server_host":
		return c.ServerHost, true
	}
	if strings.HasPrefix(key, "params.") {
		k := strings.TrimPrefix(key, "params.")
		if v, ok := c.Params[k]; ok {
			return v, true
		}
		return "", true
	}
	return "", false
}

// Render replaces {key} placeholders. Unknown placeholders are left as-is.
// For templates with conditional logic, use RenderTemplate which also handles
// {?if}/{?elif}/{?else}/{?endif} blocks.
func (c *RenderContext) Render(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		if s[i] == '{' {
			end := strings.IndexByte(s[i+1:], '}')
			if end >= 0 {
				key := s[i+1 : i+1+end]
				if v, ok := c.lookup(key); ok {
					b.WriteString(v)
					i += end + 2
					continue
				}
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// RenderTemplate renders a template string that may contain conditional blocks:
//
//	{?if CONDITION}...{?elif CONDITION}...{?else}...{?endif}
//
// CONDITION forms:
//
//	params.KEY == "value"   — equality
//	params.KEY != "value"   — inequality
//	params.KEY              — truthy (non-empty)
//
// Blocks can be nested. After conditional processing, normal {key} substitution runs.
func (c *RenderContext) RenderTemplate(s string) string {
	return c.Render(c.evalConditionals(s))
}

// evalConditionals processes {?if}/{?elif}/{?else}/{?endif} blocks recursively.
func (c *RenderContext) evalConditionals(s string) string {
	const (
		tagIf    = "{?if "
		tagElif  = "{?elif "
		tagElse  = "{?else}"
		tagEndif = "{?endif}"
	)

	for {
		// Find outermost {?if
		start := strings.Index(s, tagIf)
		if start < 0 {
			break
		}
		// Find matching {?endif} — track nesting
		depth := 0
		endifPos := -1
		for i := start; i < len(s); {
			if strings.HasPrefix(s[i:], tagIf) {
				depth++
				i += len(tagIf)
			} else if strings.HasPrefix(s[i:], tagEndif) {
				depth--
				if depth == 0 {
					endifPos = i
					break
				}
				i += len(tagEndif)
			} else {
				i++
			}
		}
		if endifPos < 0 {
			break // malformed — leave as-is
		}

		before := s[:start]
		after := s[endifPos+len(tagEndif):]
		inner := s[start : endifPos+len(tagEndif)]
		resolved := c.evalIfBlock(inner)
		s = before + resolved + after
	}
	return s
}

// evalIfBlock evaluates a single (possibly nested) {?if ...}...{?endif} block.
// Returns the content of the first branch whose condition is true.
func (c *RenderContext) evalIfBlock(block string) string {
	// Strip outer {?if COND} and {?endif}
	ifEnd := strings.Index(block, "}")
	if ifEnd < 0 {
		return block
	}
	cond := strings.TrimPrefix(block[:ifEnd+1], "{?if ")
	cond = strings.TrimSuffix(cond, "}")
	rest := block[ifEnd+1 : len(block)-len("{?endif}")]

	// Split rest into branches at top-level {?elif ...} and {?else}
	type branch struct {
		cond string // empty string = else branch
		body string
	}
	branches := []branch{{cond: cond}}
	cur := &branches[0]
	i := 0
	for i < len(rest) {
		if strings.HasPrefix(rest[i:], "{?if ") {
			// Nested if — skip to matching endif
			depth := 0
			j := i
			for j < len(rest) {
				if strings.HasPrefix(rest[j:], "{?if ") {
					depth++
					j += len("{?if ")
				} else if strings.HasPrefix(rest[j:], "{?endif}") {
					depth--
					if depth == 0 {
						j += len("{?endif}")
						break
					}
					j += len("{?endif}")
				} else {
					j++
				}
			}
			cur.body += rest[i:j]
			i = j
		} else if strings.HasPrefix(rest[i:], "{?elif ") {
			end := strings.Index(rest[i:], "}")
			if end < 0 {
				break
			}
			nc := strings.TrimPrefix(rest[i:i+end+1], "{?elif ")
			nc = strings.TrimSuffix(nc, "}")
			branches = append(branches, branch{cond: nc})
			cur = &branches[len(branches)-1]
			i += end + 1
		} else if strings.HasPrefix(rest[i:], "{?else}") {
			branches = append(branches, branch{cond: ""})
			cur = &branches[len(branches)-1]
			i += len("{?else}")
		} else {
			cur.body += string(rest[i])
			i++
		}
	}

	// Evaluate branches in order
	for _, b := range branches {
		if b.cond == "" || c.evalCondition(b.cond) {
			// Recurse for nested conditionals
			return c.evalConditionals(b.body)
		}
	}
	return ""
}

// evalCondition evaluates a simple boolean condition.
//
//	"params.key == \"value\""  → equality
//	"params.key != \"value\""  → inequality
//	"params.key"               → non-empty
func (c *RenderContext) evalCondition(cond string) bool {
	cond = strings.TrimSpace(cond)

	if idx := strings.Index(cond, " == "); idx >= 0 {
		lhs := strings.TrimSpace(cond[:idx])
		rhs := strings.Trim(strings.TrimSpace(cond[idx+4:]), `"'`)
		return c.Render("{"+lhs+"}") == rhs
	}
	if idx := strings.Index(cond, " != "); idx >= 0 {
		lhs := strings.TrimSpace(cond[:idx])
		rhs := strings.Trim(strings.TrimSpace(cond[idx+4:]), `"'`)
		return c.Render("{"+lhs+"}") != rhs
	}
	// Truthy: non-empty rendered value
	return c.Render("{"+cond+"}") != ""
}

func (c *RenderContext) RenderAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		rendered := c.Render(s)
		if rendered == "" {
			continue
		}
		out = append(out, rendered)
	}
	return out
}
