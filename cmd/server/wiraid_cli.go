package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"whispera/internal/modules/wiraid"
)

func wiraidBaseDir() string {
	if v := os.Getenv("WHISPERA_WIRAID_DIR"); v != "" {
		return v
	}
	return "/var/lib/whispera/wiraid"
}

func runWiraidCLI(args []string) {
	if len(args) == 0 {
		printWiraidUsage()
		return
	}

	switch args[0] {

	case "new":
		// Does NOT need engine — no registry required
		name := ""
		dir := ""
		for i := 1; i < len(args); i++ {
			if args[i] == "--dir" && i+1 < len(args) {
				i++
				dir = args[i]
			} else if name == "" {
				name = args[i]
			}
		}
		if name == "" {
			fmt.Fprintln(os.Stderr, "Usage: whispera wiraid new <name> [--dir <output-dir>]")
			os.Exit(1)
		}
		if dir == "" {
			dir = filepath.Join(".", name)
		}
		if err := wiraid.RunWizard(name, dir); err != nil {
			fmt.Fprintf(os.Stderr, "wizard failed: %v\n", err)
			os.Exit(1)
		}
		return

	case "validate":
		// validate can run against a manifest file without registry
		live := false
		manifestPath := ""
		rest := args[1:]
		var filtered []string
		for i := 0; i < len(rest); i++ {
			switch rest[i] {
			case "--live":
				live = true
			case "--manifest":
				if i+1 < len(rest) {
					i++
					manifestPath = rest[i]
				}
			default:
				filtered = append(filtered, rest[i])
			}
		}

		if manifestPath != "" {
			// Validate a manifest file directly — no registry needed
			runValidateManifest(manifestPath)
			return
		}

		if len(filtered) < 1 {
			fmt.Fprintln(os.Stderr, "Usage: whispera wiraid validate [--live] [--manifest <path>] <name>")
			os.Exit(1)
		}
		eng := mustEngine()
		target := filtered[0]
		if live {
			rep, err := eng.LiveValidate(target)
			if err != nil {
				fmt.Fprintf(os.Stderr, "live validate failed: %v\n", err)
				os.Exit(1)
			}
			printLiveReport(rep)
			if rep.LiveError != "" || len(rep.Errors) > 0 || !rep.StartedOK || !rep.ExitedOK {
				os.Exit(2)
			}
		} else {
			rep, err := eng.Validate(target)
			if err != nil {
				fmt.Fprintf(os.Stderr, "validate failed: %v\n", err)
				os.Exit(1)
			}
			printValidateReport(rep)
			if len(rep.Errors) > 0 {
				os.Exit(2)
			}
		}
		return
	}

	// Commands below need the engine
	eng := mustEngine()

	switch args[0] {
	case "list":
		sums := eng.Summaries()
		if len(sums) == 0 {
			fmt.Println("No modules installed.")
			return
		}
		fmt.Printf("%-24s %-8s %-8s %s\n", "NAME", "VERSION", "ENABLED", "DESCRIPTION")
		fmt.Println(strings.Repeat("-", 72))
		for _, s := range sums {
			enabled := "no"
			if s.Enabled {
				enabled = "yes"
			}
			fmt.Printf("%-24s %-8s %-8s %s\n", s.Name, s.Version, enabled, s.Description)
		}

	case "install":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: whispera wiraid install <url-or-path>")
			os.Exit(1)
		}
		name, err := eng.InstallFromURL(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "install failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ installed: %s\n", name)
		fmt.Printf("  Run: whispera wiraid validate %s\n", name)

	case "uninstall":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: whispera wiraid uninstall <name>")
			os.Exit(1)
		}
		if err := eng.Uninstall(args[1]); err != nil {
			fmt.Fprintf(os.Stderr, "uninstall failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ removed: %s\n", args[1])

	case "enable":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: whispera wiraid enable <name>")
			os.Exit(1)
		}
		if err := eng.Registry.SetEnabled(args[1], true); err != nil {
			fmt.Fprintf(os.Stderr, "enable failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ enabled: %s\n", args[1])

	case "disable":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: whispera wiraid disable <name>")
			os.Exit(1)
		}
		if err := eng.Registry.SetEnabled(args[1], false); err != nil {
			fmt.Fprintf(os.Stderr, "disable failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ disabled: %s\n", args[1])

	case "rebuild":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: whispera wiraid rebuild <name>")
			os.Exit(1)
		}
		if err := eng.Rebuild(args[1]); err != nil {
			fmt.Fprintf(os.Stderr, "rebuild failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ rebuilt: %s\n", args[1])

	default:
		printWiraidUsage()
		os.Exit(1)
	}
}

// runValidateManifest validates a module.json on disk without needing a registry entry.
func runValidateManifest(path string) {
	m, err := wiraid.LoadManifest(filepath.Dir(path))
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ failed to parse %s: %v\n", path, err)
		os.Exit(2)
	}

	fmt.Printf("\nValidating manifest: %s\n", path)
	fmt.Println(strings.Repeat("─", 52))

	hasErrors := false

	ok("schema", fmt.Sprintf("v%d", m.Schema))

	if m.Module.Name == "" {
		fail("module.name", "missing — required")
		hasErrors = true
	} else {
		ok("module.name", m.Module.Name)
	}

	if m.Module.WiraidID == "" {
		warn("module.wiraid_id", "not set — needed for pair endpoint")
	} else {
		ok("module.wiraid_id", m.Module.WiraidID)
	}

	if len(m.Runtime.Cmd) == 0 {
		fail("runtime.cmd", "empty — module cannot start")
		hasErrors = true
	} else {
		ok("runtime.cmd", strings.Join(m.Runtime.Cmd, " "))
	}

	if m.Runtime.ConfigTemplate != "" {
		ok("runtime.config_template", fmt.Sprintf("%d chars", len(m.Runtime.ConfigTemplate)))
		// check unresolved non-param placeholders
		checkUnresolved("config_template", m.Runtime.ConfigTemplate, m)
	}

	// Check params_schema consistency
	for k, ps := range m.ParamsSchema {
		if ps.Generator == "" && ps.Default == "" && !ps.Required {
			warn("params_schema."+k, "no generator, no default, not required — will always be empty")
		}
		if ps.Generator == "exec" && len(ps.ExecCmd) == 0 {
			fail("params_schema."+k, "generator=exec but exec_cmd is empty")
			hasErrors = true
		}
		if ps.Generator == "fixed" && ps.Value == "" {
			warn("params_schema."+k, "generator=fixed but value is empty")
		}
	}

	// Check that all {params.X} in templates have a schema entry
	allTemplates := []string{m.Runtime.ConfigTemplate}
	allTemplates = append(allTemplates, m.Runtime.Cmd...)
	for _, pre := range m.Runtime.PreCmd {
		allTemplates = append(allTemplates, pre...)
	}
	for _, post := range m.Runtime.PostCmd {
		allTemplates = append(allTemplates, post...)
	}
	for _, tmpl := range allTemplates {
		for _, ph := range extractParamPlaceholders(tmpl) {
			if _, declared := m.ParamsSchema[ph]; !declared {
				fail("params_schema", fmt.Sprintf("{params.%s} used in template but not declared in params_schema", ph))
				hasErrors = true
			}
		}
	}

	// URI spec
	if m.Module.URI != nil {
		u := m.Module.URI
		if len(u.Schemes) == 0 {
			fail("uri.schemes", "empty — no schemes defined")
			hasErrors = true
		}
		if u.Style != "url" && u.Style != "base64_json" {
			fail("uri.style", fmt.Sprintf("%q — must be 'url' or 'base64_json'", u.Style))
			hasErrors = true
		}
		// Check that mapped params exist
		targets := map[string]string{}
		if u.SchemeTo != "" {
			targets[u.SchemeTo] = "scheme_to"
		}
		if u.UserinfoTo != "" {
			targets[u.UserinfoTo] = "userinfo_to"
		}
		if u.UserinfoUserTo != "" {
			targets[u.UserinfoUserTo] = "userinfo_user_to"
		}
		if u.UserinfoPassTo != "" {
			targets[u.UserinfoPassTo] = "userinfo_pass_to"
		}
		if u.HostTo != "" {
			targets[u.HostTo] = "host_to"
		}
		if u.PortTo != "" {
			targets[u.PortTo] = "port_to"
		}
		if u.PathTo != "" {
			targets[u.PathTo] = "path_to"
		}
		if u.FragmentTo != "" {
			targets[u.FragmentTo] = "fragment_to"
		}
		for _, v := range u.QueryMap {
			targets[v] = "query_map"
		}
		for _, v := range u.JSONMap {
			targets[v] = "json_map"
		}
		missingParams := []string{}
		for param, field := range targets {
			if _, ok := m.ParamsSchema[param]; !ok {
				missingParams = append(missingParams, fmt.Sprintf("%s → %q not in params_schema", field, param))
			}
		}
		if len(missingParams) > 0 {
			for _, msg := range missingParams {
				fail("uri", msg)
			}
			hasErrors = true
		} else {
			ok("uri", fmt.Sprintf("schemes=%v style=%s", u.Schemes, u.Style))
		}
	}

	fmt.Println(strings.Repeat("─", 52))
	if hasErrors {
		fmt.Println("✗ manifest has errors — fix them before installing")
		os.Exit(2)
	}
	fmt.Println("✓ manifest looks valid")
}

func checkUnresolved(label, tmpl string, m wiraid.Manifest) {
	for _, ph := range extractParamPlaceholders(tmpl) {
		if _, ok := m.ParamsSchema[ph]; !ok {
			warn(label, fmt.Sprintf("{params.%s} has no entry in params_schema", ph))
		}
	}
}

func extractParamPlaceholders(s string) []string {
	var out []string
	for {
		i := strings.Index(s, "{params.")
		if i < 0 {
			break
		}
		rest := s[i+8:]
		j := strings.IndexByte(rest, '}')
		if j < 0 {
			break
		}
		out = append(out, rest[:j])
		s = rest[j+1:]
	}
	return out
}

func ok(field, value string)   { fmt.Printf("  ✓ %-28s %s\n", field, value) }
func warn(field, msg string)   { fmt.Printf("  ⚠ %-28s %s\n", field, msg) }
func fail(field, msg string)   { fmt.Printf("  ✗ %-28s %s\n", field, msg) }

func printValidateReport(rep *wiraid.ValidateReport) {
	fmt.Printf("\nValidating module: %s\n", rep.Name)
	fmt.Println(strings.Repeat("─", 52))

	if rep.BinaryExists {
		ok("binary", rep.BinaryPath)
	} else if rep.BinaryPath == "" {
		fail("binary", "not built — run: whispera wiraid rebuild "+rep.Name)
	} else {
		fail("binary", "missing on disk: "+rep.BinaryPath)
	}

	if len(rep.Errors) == 0 && len(rep.MissingParam) == 0 {
		ok("params", fmt.Sprintf("%d filled", len(rep.Params)))
	}
	for _, p := range rep.MissingParam {
		fail("param."+p, "required but not set — run: whispera wiraid enable "+rep.Name+" to auto-generate")
	}

	if len(rep.RenderedCmd) > 0 {
		ok("cmd", strings.Join(rep.RenderedCmd, " "))
	} else {
		fail("cmd", "empty after render")
	}

	if rep.ConfigSample != "" {
		ok("config_template", "renders OK")
	}

	if len(rep.PairExports) > 0 {
		if rep.PublicHost == "" {
			warn("pair_exports", "WHISPERA_PUBLIC_HOST not set — {server_host} will be empty")
		} else {
			ok("pair_exports", fmt.Sprintf("%d keys, host=%s", len(rep.PairExports), rep.PublicHost))
		}
	}

	for _, w := range rep.Warnings {
		warn("warning", w)
	}
	for _, e := range rep.Errors {
		fail("error", e)
	}

	fmt.Println(strings.Repeat("─", 52))
	if len(rep.Errors) > 0 {
		fmt.Println("✗ validation failed")
	} else {
		fmt.Println("✓ all checks passed")
		if rep.ConfigSample != "" {
			fmt.Println("\nRendered config sample:")
			fmt.Println(rep.ConfigSample)
		}
	}
}

func printLiveReport(rep *wiraid.LiveReport) {
	printValidateReport(rep.ValidateReport)
	fmt.Printf("\n  live.started_ok  %v\n", rep.StartedOK)
	fmt.Printf("  live.exited_ok   %v\n", rep.ExitedOK)
	if rep.LivePort > 0 {
		fmt.Printf("  live.port        %d\n", rep.LivePort)
	}
	for _, s := range rep.Steps {
		fmt.Printf("  live.step        %s\n", s)
	}
	if rep.LiveError != "" {
		fmt.Printf("  live.error       %s\n", rep.LiveError)
	}
}

func mustEngine() *wiraid.Engine {
	eng, err := wiraid.NewEngine(wiraidBaseDir())
	if err != nil {
		fmt.Fprintf(os.Stderr, "wiraid init failed: %v\n", err)
		os.Exit(1)
	}
	return eng
}

// Summaries wraps engine list — engine exposes it via Registry
func init() {
	_ = json.Marshal // keep import used
}

func printWiraidUsage() {
	fmt.Fprintln(os.Stderr, `Usage: whispera wiraid <command>

Module authoring:
  new <name> [--dir <path>]         Interactive wizard — create module.json
  validate --manifest <path>        Check a module.json file (no install needed)

Module management:
  list                              List installed modules
  install <url-or-path>             Install from git URL, archive URL, or local dir
  uninstall <name>                  Remove module
  enable <name>                     Enable module (auto-generates params)
  disable <name>                    Disable module
  rebuild <name>                    Rebuild from source

Diagnostics:
  validate <name>                   Dry-run check on installed module
  validate --live <name>            Full start/stop test with mock binary

Env:
  WHISPERA_WIRAID_DIR               Override default dir (/var/lib/whispera/wiraid)
  WHISPERA_PUBLIC_HOST              Override public hostname for pair_exports`)
}
