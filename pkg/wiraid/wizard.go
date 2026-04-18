package wiraid

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type wizardState struct {
	r   *bufio.Reader
	out io.Writer
}

func (w *wizardState) ask(prompt, defaultVal string) string {
	if defaultVal != "" {
		fmt.Fprintf(w.out, "  %s [%s]: ", prompt, defaultVal)
	} else {
		fmt.Fprintf(w.out, "  %s: ", prompt)
	}
	line, _ := w.r.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return defaultVal
	}
	return line
}

func (w *wizardState) choose(prompt string, options []string, defaultIdx int) string {
	opts := strings.Join(options, " / ")
	fmt.Fprintf(w.out, "  %s (%s) [%s]: ", prompt, opts, options[defaultIdx])
	line, _ := w.r.ReadString('\n')
	line = strings.TrimSpace(strings.ToLower(line))
	if line == "" {
		return options[defaultIdx]
	}
	for _, o := range options {
		if strings.EqualFold(line, o) {
			return o
		}
	}
	fmt.Fprintf(w.out, "  ! Invalid choice, using default: %s\n", options[defaultIdx])
	return options[defaultIdx]
}

func (w *wizardState) yesno(prompt string, defaultYes bool) bool {
	def := "n"
	if defaultYes {
		def = "y"
	}
	ans := w.ask(prompt+" (y/n)", def)
	return strings.HasPrefix(strings.ToLower(ans), "y")
}

// RunWizard interactively builds a Manifest for a new module and saves it to dir.
func RunWizard(name, dir string) error {
	w := &wizardState{
		r:   bufio.NewReader(os.Stdin),
		out: os.Stdout,
	}

	fmt.Fprintf(w.out, "\n=== WIRAID module wizard: %s ===\n\n", name)
	fmt.Fprintln(w.out, "Press Enter to accept defaults shown in [brackets].")

	m := Manifest{Schema: 2}
	m.Module.Name = name
	m.Module.Lang = LangBinary
	m.Module.Version = "0.1.0"
	m.Capabilities.Transport = true
	m.Runtime.ConfigPath = "config.json"
	m.Runtime.Protocol = "socks5"
	m.Runtime.PortDiscovery = PortDiscovery{Mode: "fixed"}
	m.Runtime.Ready = ReadySignal{Mode: "tcp_connect", Timeout: 5000}
	m.ParamsSchema = map[string]ParamSchema{}

	// Basic info
	m.Module.Description = w.ask("Short description", "")
	m.Module.WiraidID = w.ask("Unique wiraid_id (used in pair endpoints)", name)

	side := w.choose("Is this a client or server module?", []string{"client", "server"}, 0)
	isServer := side == "server"

	// Platforms
	fmt.Fprintln(w.out, "\n  Supported platforms (space-separated).")
	fmt.Fprintln(w.out, "  Available: linux-x86_64 linux-arm64 windows-x86_64 darwin-x86_64 darwin-arm64")
	platStr := w.ask("Platforms", func() string {
		if isServer {
			return "linux-x86_64"
		}
		return "linux-x86_64 windows-x86_64"
	}())
	for _, p := range strings.Fields(platStr) {
		m.Module.Platforms = append(m.Module.Platforms, p)
	}

	// Peer
	if w.yesno("\nDoes this module have a peer counterpart (client↔server pair)?", true) {
		peerID := w.ask("Peer wiraid_id", func() string {
			if isServer {
				return strings.TrimSuffix(name, "-server") + "-client"
			}
			return strings.TrimSuffix(name, "-client") + "-server"
		}())
		m.Module.Peer = &PeerSpec{ID: peerID}
	}

	// Command style
	fmt.Fprintln(w.out, "\n--- Command configuration ---")
	cmdStyle := w.choose("How does the binary receive its configuration?", []string{"config-file", "flags-only"}, 0)

	if cmdStyle == "flags-only" {
		fmt.Fprintln(w.out, "  Enter the command template. Available placeholders:")
		fmt.Fprintln(w.out, "    {binary}  {listen_host}  {listen_port}  {params.NAME}")
		rawCmd := w.ask("Command", "{binary} -l {listen_host}:{listen_port}")
		m.Runtime.Cmd = strings.Fields(rawCmd)
		m.Runtime.ConfigPath = ""
		m.Runtime.ConfigTemplate = ""
	} else {
		cfgFmt := w.choose("Config file format", []string{"json", "yaml"}, 0)
		if cfgFmt == "yaml" {
			m.Runtime.ConfigPath = "config.yaml"
		}

		fmt.Fprintln(w.out, "  Enter the main command template. Placeholders:")
		fmt.Fprintln(w.out, "    {binary}  {config_path}  {module_dir}  {listen_host}  {listen_port}")
		rawCmd := w.ask("Command", "{binary} -c {config_path}")
		m.Runtime.Cmd = strings.Fields(rawCmd)

		if w.yesno("Does it need a pre-start command (e.g. 'apply config')?", false) {
			rawPre := w.ask("Pre-command template", "{binary} apply config {config_path}")
			m.Runtime.PreCmd = [][]string{strings.Fields(rawPre)}
		}
		if w.yesno("Does it need a post-stop command (e.g. daemon stop)?", false) {
			rawPost := w.ask("Post-command template", "{binary} stop")
			m.Runtime.PostCmd = [][]string{strings.Fields(rawPost)}
		}
	}

	// Ready signal
	fmt.Fprintln(w.out, "\n--- Ready detection ---")
	readyMode := w.choose("How to detect the module is ready?", []string{"tcp_connect", "stdout_contains", "delay"}, 0)
	m.Runtime.Ready.Mode = readyMode
	if readyMode == "stdout_contains" {
		m.Runtime.Ready.Value = w.ask("String to look for in stdout", "listening")
	}
	timeoutStr := w.ask("Timeout ms", "5000")
	fmt.Sscanf(timeoutStr, "%d", &m.Runtime.Ready.Timeout)
	if m.Runtime.Ready.Timeout <= 0 {
		m.Runtime.Ready.Timeout = 5000
	}

	// Protocol output
	m.Runtime.Protocol = w.choose("Protocol this module exposes locally", []string{"socks5", "tcp", "http"}, 0)

	// Params
	fmt.Fprintln(w.out, "\n--- Parameters ---")
	fmt.Fprintln(w.out, "  Params are values injected into config_template as {params.NAME}.")
	fmt.Fprintln(w.out, "  Generators: random_hex, random_alnum, fixed, env, self_signed_cert, exec")

	if isServer {
		// Auto-suggest common server params
		if w.yesno("Add auto-generated password/secret param?", true) {
			pname := w.ask("Param name", "password")
			plen := 0
			fmt.Sscanf(w.ask("Length (hex bytes)", "24"), "%d", &plen)
			if plen <= 0 {
				plen = 24
			}
			m.ParamsSchema[pname] = ParamSchema{Generator: "random_hex", Length: plen}
		}
		if w.yesno("Add auto-generated listen port param?", false) {
			portVal := w.ask("Port value", "8443")
			m.ParamsSchema["listen_port"] = ParamSchema{Generator: "fixed", Value: portVal}
		}
		if w.yesno("Add TLS cert/key (self-signed, auto-generated)?", false) {
			m.ParamsSchema["cert_path"] = ParamSchema{Generator: "self_signed_cert"}
			m.ParamsSchema["key_path"] = ParamSchema{Generator: "fixed", Value: "tls.key"}
		}
		if w.yesno("Add exec-generated keypair (e.g. xray x25519)?", false) {
			binaryArg := w.ask("Binary argument to generate keys", "x25519")
			privRe := w.ask("Regex for private key", "Private key:\\s*(\\S+)")
			pubRe := w.ask("Regex for public key", "Public key:\\s*(\\S+)")
			m.ParamsSchema["private_key"] = ParamSchema{
				Generator: "exec", ExecCmd: []string{"{binary}", binaryArg},
				ExecRegex: privRe, ExecGroup: 1,
			}
			m.ParamsSchema["public_key"] = ParamSchema{
				Generator: "exec", ExecCmd: []string{"{binary}", binaryArg},
				ExecRegex: pubRe, ExecGroup: 1,
			}
		}
		// pair_exports
		if m.Module.Peer != nil && w.yesno("Add pair_exports (params the client will receive)?", true) {
			fmt.Fprintln(w.out, "  Enter key=template pairs. Templates support {server_host} and {params.NAME}.")
			fmt.Fprintln(w.out, "  Empty line to finish.")
			m.Module.PairExports = map[string]string{}
			defaults := map[string]string{
				"server_host": "{server_host}",
				"server_port": "{params.listen_port}",
				"password":    "{params.password}",
			}
			for k, v := range defaults {
				if _, ok := m.ParamsSchema[k]; ok || k == "server_host" || k == "listen_port" {
					if w.yesno(fmt.Sprintf("  Export %q = %q?", k, v), true) {
						m.Module.PairExports[k] = v
					}
				}
			}
			for {
				extra := w.ask("  Extra export key (or Enter to finish)", "")
				if extra == "" {
					break
				}
				val := w.ask(fmt.Sprintf("  Template for %q", extra), "{params."+extra+"}")
				m.Module.PairExports[extra] = val
			}
		}
	} else {
		// Client: required params from server
		if m.Module.Peer != nil {
			defaultClientParams := []string{"server_host", "server_port", "password", "sni"}
			fmt.Fprintln(w.out, "  Suggest common client params (required, filled via pair or URI):")
			for _, p := range defaultClientParams {
				if w.yesno(fmt.Sprintf("  Add required param %q?", p), true) {
					m.ParamsSchema[p] = ParamSchema{Type: "string", Required: true}
				}
			}
		}

		// URI spec
		fmt.Fprintln(w.out, "\n--- Share-link URI ---")
		if w.yesno("Does this module accept share-link URIs (vless://, hy2://, etc.)?", false) {
			spec := URISpec{}
			schemeStr := w.ask("URI scheme(s), space-separated", "")
			for _, s := range strings.Fields(schemeStr) {
				spec.Schemes = append(spec.Schemes, s)
			}
			spec.Style = w.choose("URI style", []string{"url", "base64_json"}, 0)
			if spec.Style == "url" {
				fmt.Fprintln(w.out, "  Map URI parts to param names (Enter to skip):")
				spec.HostTo = w.ask("  host → param", "server_host")
				spec.PortTo = w.ask("  port → param", "server_port")
				spec.UserinfoTo = w.ask("  userinfo (uuid/password/token) → param", "password")
				spec.FragmentTo = w.ask("  fragment (#remark) → param (or Enter to skip)", "remark")
				fmt.Fprintln(w.out, "  Query params mapping: enter query_key=param_name pairs. Empty line to finish.")
				spec.QueryMap = map[string]string{}
				for {
					pair := w.ask("  query mapping", "")
					if pair == "" {
						break
					}
					parts := strings.SplitN(pair, "=", 2)
					if len(parts) == 2 {
						spec.QueryMap[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
					}
				}
				if len(spec.QueryMap) == 0 {
					spec.QueryMap = nil
				}
			} else {
				fmt.Fprintln(w.out, "  JSON field mapping: enter json_field=param_name pairs. Empty line to finish.")
				spec.JSONMap = map[string]string{}
				for {
					pair := w.ask("  json mapping", "")
					if pair == "" {
						break
					}
					parts := strings.SplitN(pair, "=", 2)
					if len(parts) == 2 {
						spec.JSONMap[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
					}
				}
			}
			if len(spec.Schemes) > 0 {
				m.Module.URI = &spec
			}
		}
	}

	// Extra params
	fmt.Fprintln(w.out, "\n  Add any additional params? Empty name to finish.")
	for {
		pname := w.ask("  Param name", "")
		if pname == "" {
			break
		}
		gen := w.choose(fmt.Sprintf("  Generator for %q", pname),
			[]string{"none", "random_hex", "random_alnum", "fixed", "env", "exec"}, 0)
		ps := ParamSchema{Type: "string"}
		switch gen {
		case "none":
			ps.Required = w.yesno("  Required (must be provided by user/pair)?", true)
			ps.Description = w.ask("  Description", "")
		case "random_hex":
			plen := 0
			fmt.Sscanf(w.ask("  Length (bytes)", "16"), "%d", &plen)
			if plen <= 0 {
				plen = 16
			}
			ps.Generator = "random_hex"
			ps.Length = plen
		case "random_alnum":
			plen := 0
			fmt.Sscanf(w.ask("  Length (chars)", "16"), "%d", &plen)
			if plen <= 0 {
				plen = 16
			}
			ps.Generator = "random_alnum"
			ps.Length = plen
		case "fixed":
			ps.Generator = "fixed"
			ps.Value = w.ask("  Value", "")
		case "env":
			ps.Generator = "env"
			ps.Env = w.ask("  Environment variable name", strings.ToUpper(pname))
		case "exec":
			rawCmd := w.ask("  Exec command (use {binary} as placeholder)", "{binary} generate")
			ps.Generator = "exec"
			ps.ExecCmd = strings.Fields(rawCmd)
			ps.ExecRegex = w.ask("  Regex to extract value (capture group 1)", "")
		}
		m.ParamsSchema[pname] = ps
	}

	// Write
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	outPath := filepath.Join(dir, "module.json")
	if err := SaveManifest(dir, m); err != nil {
		return err
	}

	fmt.Fprintf(w.out, "\n✓ Written: %s\n", outPath)
	fmt.Fprintf(w.out, "\nNext steps:\n")
	fmt.Fprintf(w.out, "  1. Copy your binary into: %s/\n", dir)
	fmt.Fprintf(w.out, "  2. whispera wiraid install %s\n", dir)
	fmt.Fprintf(w.out, "  3. whispera wiraid validate %s\n", m.Module.Name)
	fmt.Fprintf(w.out, "  4. whispera wiraid enable %s\n\n", m.Module.Name)
	return nil
}
