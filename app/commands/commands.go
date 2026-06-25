package commands

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
	"whispera/app/db"
	"whispera/common/ipdetect"
	"whispera/core/apiserver"
	"whispera/core/config"
	"whispera/core/protocol"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/curve25519"
)

const decoyCertDir = "/etc/whispera/decoy_certs"

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

func stripURLScheme(publicURL string) string {
	s := strings.TrimPrefix(strings.TrimPrefix(publicURL, "https://"), "http://")
	s = strings.TrimRight(s, "/")
	if h, _, err := net.SplitHostPort(s); err == nil {
		return h
	}
	return s
}

func RunX25519Cmd() {
	private := make([]byte, 32)
	if _, err := rand.Read(private); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Private Key: %s\n", base64.StdEncoding.EncodeToString(private))
	fmt.Printf("Public Key:  %s\n", base64.StdEncoding.EncodeToString(public))
	os.Exit(0)
}

func RunPubkeyCmd() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "whispera pubkey <private_key>")
		os.Exit(1)
	}
	privateKeyString := strings.TrimSpace(os.Args[2])

	private, err := base64.StdEncoding.DecodeString(privateKeyString)

	if err != nil || len(private) != 32 {
		fmt.Fprintf(os.Stderr, "Error: invalid private key (must be 32 bytes Base64)\n")
		os.Exit(1)
	}
	pub, _ := curve25519.X25519(private, curve25519.Basepoint)
	fmt.Println(base64.StdEncoding.EncodeToString(pub))
	os.Exit(0)
}

func RunCreateAdminCmd() {
	createAdminCmd := flag.NewFlagSet("create-admin", flag.ExitOnError)
	email := createAdminCmd.String("email", "", "Admin email")
	password := createAdminCmd.String("password", "", "Admin password")
	dbURL := createAdminCmd.String("db", "", "PostgreSQL URL")

	createAdminCmd.Parse(os.Args[2:])

	if *email == "" || *password == "" || *dbURL == "" {
		fmt.Fprintln(os.Stderr, "whispera create-admin -email <email> -password <pass> -db <postgres_url>")
		os.Exit(1)
	}

	cfg := db.DefaultConfig()
	cfg.URL = *dbURL
	database, err := db.New(cfg)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to connect to DB: %v\n", err)
		os.Exit(1)
	}

	defer database.Close()

	ctx := context.Background()
	user, err := database.GetUserByEmail(ctx, *email)
	if err != nil {
		user, err = database.CreateUser(ctx, *email, *password, 0, nil, "http2", "browser", "vk", "", "")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create user: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("User %s created\n", *email)
	} else {
		if err := database.UpdateUser(ctx, user.ID, *email, *password); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to update password: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("User %s password updated\n", *email)
	}

	if err := database.SetAdmin(ctx, user.ID, true); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to set admin: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("User %s is now an admin\n", *email)
	os.Exit(0)
}

func RunCreateKeyCmd() {
	createKeyCmd := flag.NewFlagSet("create-key", flag.ExitOnError)
	user := createKeyCmd.String("user", "", "User identifier (used as the whispera auth username)")
	port := createKeyCmd.Int("port", 0, "Dedicated listen port for this user (whispera TCP, or grpc, depending on -transport)")
	quicPort := createKeyCmd.Int("quic-port", 0, "Dedicated QUIC port for this user (only with -quic enable; 0 = reuse whispera.quic_listen_addr's port)")
	cfgPath := createKeyCmd.String("config", "/etc/whispera/config.yaml", "Path to config.yaml")
	trafficLimit := createKeyCmd.Int64("traffic-limit", 0, "Traffic limit in bytes (0 = unlimited)")
	quicFlag := createKeyCmd.String("quic", "disable", "Carry the whispera tunnel over QUIC instead of TCP (enable/disable, only applies to -transport whispera)")
	transportFlag := createKeyCmd.String("transport", "whispera", "Base transport for this key: whispera, grpc, or yadisk")
	yadiskToken := createKeyCmd.String("yadisk-token", "", "Yandex.Disk OAuth token (only with -transport yadisk; saved to server config if not already set there)")
	yadiskSession := createKeyCmd.String("yadisk-session", "", "Yandex.Disk session/folder id (only with -transport yadisk; auto-generated if empty)")
	neuralFlag := createKeyCmd.String("neural", "enable", "Use neural-network traffic shaping (RL agents + GAN padding) for this user (enable/disable)")
	sniFlag := createKeyCmd.String("sni", "", "Clone this real domain's TLS certificate and present it via SNI for this key (only with -transport whispera; empty = auto-picked from a default pool, or the server's ACME domain if configured)")

	createKeyCmd.Parse(os.Args[2:])

	if *user == "" || *port == 0 {
		fmt.Fprintln(os.Stderr, "whispera create-key -user <name> -port <port> [-config <path>] [-traffic-limit <bytes>] [-quic enable|disable] [-quic-port <port>] [-transport whispera|grpc|yadisk] [-yadisk-token <token>] [-yadisk-session <id>] [-neural enable|disable] [-sni <real-domain>]")
		os.Exit(1)
	}
	disableNeural := strings.EqualFold(*neuralFlag, "disable")
	if !disableNeural && !strings.EqualFold(*neuralFlag, "enable") {
		fmt.Fprintf(os.Stderr, "Error: -neural must be \"enable\" or \"disable\", got %q\n", *neuralFlag)
		os.Exit(1)
	}
	if *port < 1 || *port > 65535 {
		fmt.Fprintf(os.Stderr, "Error: invalid port %d\n", *port)
		os.Exit(1)
	}
	if *quicPort != 0 && (*quicPort < 1 || *quicPort > 65535) {
		fmt.Fprintf(os.Stderr, "Error: invalid quic-port %d\n", *quicPort)
		os.Exit(1)
	}
	enableQUIC := strings.EqualFold(*quicFlag, "enable")
	if !enableQUIC && !strings.EqualFold(*quicFlag, "disable") {
		fmt.Fprintf(os.Stderr, "Error: -quic must be \"enable\" or \"disable\", got %q\n", *quicFlag)
		os.Exit(1)
	}
	altTransport := strings.ToLower(*transportFlag)
	switch altTransport {
	case "whispera", "grpc", "yadisk":
	default:
		fmt.Fprintf(os.Stderr, "Error: -transport must be \"whispera\", \"grpc\" or \"yadisk\", got %q\n", *transportFlag)
		os.Exit(1)
	}

	cfgProvider, err := config.New(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if err := cfgProvider.Load(*cfgPath); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load %s: %v\n", *cfgPath, err)
		os.Exit(1)
	}
	sc := cfgProvider.GetConfig()

	if altTransport == "yadisk" {
		newOAuth := sc.YaDisk.OAuthToken
		newSession := sc.YaDisk.SessionID
		newEnabled := sc.YaDisk.Enabled
		needsUpdate := false

		if *yadiskToken != "" && *yadiskToken != newOAuth {
			newOAuth = *yadiskToken
			newEnabled = true
			needsUpdate = true
		}
		if *yadiskSession != "" && *yadiskSession != newSession {
			newSession = *yadiskSession
			needsUpdate = true
		} else if newSession == "" && newOAuth != "" {
			if gen, err := randomHex(8); err == nil {
				newSession = gen
				needsUpdate = true
			}
		}

		if needsUpdate {
			if err := cfgProvider.Update(func(sc *config.ServerConfig) {
				sc.YaDisk.OAuthToken = newOAuth
				sc.YaDisk.SessionID = newSession
				sc.YaDisk.Enabled = newEnabled
			}); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to update %s: %v\n", *cfgPath, err)
				os.Exit(1)
			}
			sc = cfgProvider.GetConfig()
			fmt.Println("Saved yadisk.oauth_token/session_id to server config (restart server to activate)")
		}
	}

	effectiveTransport := altTransport
	if altTransport == "grpc" && (!sc.GRPC.Enabled || sc.GRPC.ListenAddr == "") {
		fmt.Fprintln(os.Stderr, "Warning: -transport=grpc requested but grpc.enabled/listen_addr is not configured on this server — key generated with whispera transport instead")
		effectiveTransport = "whispera"
	}
	if altTransport == "yadisk" && (!sc.YaDisk.Enabled || sc.YaDisk.OAuthToken == "") {
		fmt.Fprintln(os.Stderr, "Warning: -transport=yadisk requested but yadisk.enabled/oauth_token is not configured on this server (pass -yadisk-token to set it) — key generated with whispera transport instead")
		effectiveTransport = "whispera"
	}

	_, chmPortStr, _ := net.SplitHostPort(sc.Whispera.ListenAddr)
	chmPort, _ := strconv.Atoi(chmPortStr)

	switch effectiveTransport {
	case "grpc":
		_, grpcPortStr, _ := net.SplitHostPort(sc.GRPC.ListenAddr)
		grpcPort, _ := strconv.Atoi(grpcPortStr)
		portTaken := *port == grpcPort
		for _, p := range sc.GRPC.ExtraPorts {
			if p == *port {
				portTaken = true
			}
		}
		if !portTaken {
			err = cfgProvider.Update(func(sc *config.ServerConfig) {
				sc.GRPC.ExtraPorts = append(sc.GRPC.ExtraPorts, *port)
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to update %s: %v\n", *cfgPath, err)
				os.Exit(1)
			}
			fmt.Printf("gRPC will also listen on port %d (restart server to activate)\n", *port)
		} else {
			fmt.Printf("Port %d is already a gRPC listener — reusing it\n", *port)
		}
		if err := apiserver.OpenFirewallPort(*port); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: firewall rule not applied: %v\n", err)
		} else {
			fmt.Printf("Opened port %d in ufw (tcp+udp)\n", *port)
		}
	case "yadisk":
	default:
		portTaken := *port == chmPort
		for _, in := range sc.Inbounds {
			if in.Port == *port {
				portTaken = true
			}
		}
		for _, p := range sc.Whispera.ExtraPorts {
			if p == *port {
				portTaken = true
			}
		}
		if !portTaken {
			err = cfgProvider.Update(func(sc *config.ServerConfig) {
				sc.Whispera.ExtraPorts = append(sc.Whispera.ExtraPorts, *port)
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to update %s: %v\n", *cfgPath, err)
				os.Exit(1)
			}
			fmt.Printf("Whispera will also listen on port %d (restart server to activate)\n", *port)
		} else {
			fmt.Printf("Port %d is already a whispera listener — reusing it\n", *port)
		}
		if err := apiserver.OpenFirewallPort(*port); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: firewall rule not applied: %v\n", err)
		} else {
			fmt.Printf("Opened port %d in ufw (tcp+udp)\n", *port)
		}
	}

	privateKeyB64, publicKeyB64, err := apiserver.CLIUpsertUser(*user, *trafficLimit, disableNeural)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create user: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("User %s registered for live auth (/etc/whispera/users.json)\n", *user)

	serverHost := stripURLScheme(sc.Server.PublicURL)
	if serverHost == "" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		serverHost, _ = ipdetect.DetectServerIP(ctx)
		cancel()
	}
	if serverHost == "" {
		serverHost = "<server_ip>"
	}
	serverAddr := fmt.Sprintf("%s:%d", serverHost, *port)

	serverPubKeyB64 := ""
	if sc.Server.PrivateKey != "" {
		serverPubKeyB64 = apiserver.DerivePublicKeyB64(sc.Server.PrivateKey)
	}

	altOpts := apiserver.AltTransportKeyOptions{}
	switch effectiveTransport {
	case "grpc":
		altOpts.GRPCAddr = fmt.Sprintf("%s:%d", serverHost, *port)
		altOpts.GRPCServerName = sc.GRPC.ServerName
		altOpts.GRPCUseTLS = sc.GRPC.TLSCert != ""
	case "yadisk":
		altOpts.YaDiskOAuthToken = sc.YaDisk.OAuthToken
		altOpts.YaDiskSessionID = sc.YaDisk.SessionID
	}

	whisperaOpts := apiserver.WhisperaKeyOptions{}
	if effectiveTransport == "whispera" {
		whisperaQUICAddr := ""
		if enableQUIC {
			if sc.Whispera.QUICListenAddr == "" {
				fmt.Fprintln(os.Stderr, "Warning: -quic=enable requested but whispera.quic_listen_addr is not configured on this server — key generated without QUIC")
			} else {
				quicHost, quicListenPortStr, err := net.SplitHostPort(sc.Whispera.QUICListenAddr)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Warning: invalid whispera.quic_listen_addr %q: %v — key generated without QUIC\n", sc.Whispera.QUICListenAddr, err)
				} else {
					effectiveQUICPortStr := quicListenPortStr
					if *quicPort != 0 && strconv.Itoa(*quicPort) != quicListenPortStr {
						effectiveQUICPortStr = strconv.Itoa(*quicPort)
						quicPortTaken := false
						for _, p := range sc.Whispera.QUICExtraPorts {
							if p == *quicPort {
								quicPortTaken = true
							}
						}
						if !quicPortTaken {
							if err := cfgProvider.Update(func(sc *config.ServerConfig) {
								sc.Whispera.QUICExtraPorts = append(sc.Whispera.QUICExtraPorts, *quicPort)
							}); err != nil {
								fmt.Fprintf(os.Stderr, "Failed to update %s: %v\n", *cfgPath, err)
								os.Exit(1)
							}
							fmt.Printf("QUIC will also listen on port %d (restart server to activate)\n", *quicPort)
						} else {
							fmt.Printf("QUIC port %d is already a listener — reusing it\n", *quicPort)
						}
						if err := apiserver.OpenFirewallPort(*quicPort); err != nil {
							fmt.Fprintf(os.Stderr, "Warning: firewall rule not applied: %v\n", err)
						} else {
							fmt.Printf("Opened port %d in ufw (tcp+udp)\n", *quicPort)
						}
					}
					whisperaQUICAddr = net.JoinHostPort(quicHost, effectiveQUICPortStr)
				}
			}
		}

		whisperaSNI := sc.Whispera.Domain
		sniToClone := *sniFlag
		if sniToClone == "" && whisperaSNI == "" {
			sniToClone = protocol.DefaultSNIFor(*user)
		}
		servedCertPath := sc.Whispera.TLSCert
		if sniToClone != "" {
			certPath, keyPath, ok := protocol.SNICertPaths(decoyCertDir, sniToClone)
			if !ok {
				fmt.Fprintf(os.Stderr, "Warning: SNI %q is not a valid hostname — falling back to the server's default cert\n", sniToClone)
			} else {
				os.MkdirAll(decoyCertDir, 0755)
				info, err := protocol.CloneCertToFiles(sniToClone, certPath, keyPath)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Warning: failed to clone certificate for SNI %q: %v — falling back to the server's default cert\n", sniToClone, err)
				} else {
					whisperaSNI = sniToClone
					servedCertPath = certPath
					fmt.Printf("Cloned TLS certificate for SNI %s (subject=%s, valid %s -> %s)\n",
						sniToClone, info.Subject, info.NotBefore.Format(time.RFC3339), info.NotAfter.Format(time.RFC3339))
				}
			}
		}

		whisperaCertPin := ""
		if servedCertPath != "" {
			pin, pinErr := apiserver.ComputeWhisperaCertPin(servedCertPath)
			if pinErr != nil {
				fmt.Fprintf(os.Stderr, "Warning: could not compute whispera cert pin: %v (client will not pin the server cert — vulnerable to MITM)\n", pinErr)
			} else {
				whisperaCertPin = pin
			}
		} else {
			fmt.Fprintln(os.Stderr, "Warning: no static cert file to pin (pure ACME mode) — client will not pin the server cert and is vulnerable to MITM")
		}

		whisperaOpts = apiserver.WhisperaKeyOptions{
			Addr:     fmt.Sprintf("%s:%s", serverHost, chmPortStr),
			SNI:      whisperaSNI,
			QUICAddr: whisperaQUICAddr,
			CertPin:  whisperaCertPin,
		}
	}

	connectionURI, err := apiserver.CLIBuildConnectionKey(*user, serverAddr, serverPubKeyB64, "whispera", whisperaOpts, altOpts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to build connection key: %v\n", err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println("=== Client config ===")
	fmt.Printf("User:        %s\n", *user)
	fmt.Printf("Server:      %s\n", serverAddr)
	fmt.Printf("Private Key: %s\n", privateKeyB64)
	fmt.Printf("Public Key:  %s\n", publicKeyB64)
	switch effectiveTransport {
	case "grpc":
		fmt.Printf("Transport:   grpc (%s)\n", altOpts.GRPCAddr)
	case "yadisk":
		fmt.Println("Transport:   yadisk")
	default:
		if whisperaOpts.CertPin != "" {
			fmt.Printf("Cert Pin:    %s (embedded in key — protects against TLS MITM)\n", whisperaOpts.CertPin)
		} else {
			fmt.Println("Cert Pin:    none (whispera.domain is set — cert rotates under ACME, so it isn't pinned)")
		}
		if whisperaOpts.QUICAddr != "" {
			fmt.Printf("Transport:   whispera over QUIC (%s)\n", whisperaOpts.QUICAddr)
		} else {
			fmt.Println("Transport:   whispera over TCP")
		}
	}
	fmt.Printf("Key:         %s\n", connectionURI)
	fmt.Println()
	fmt.Println("Restart the whispera server for the new user/inbound to take effect.")
	os.Exit(0)
}

func RunGenerateSubCmd() {
	genSubCmd := flag.NewFlagSet("generate-sub", flag.ExitOnError)
	name := genSubCmd.String("name", "", "Subscription name")
	usersCSV := genSubCmd.String("users", "", "Comma-separated list of usernames created via create-key")
	cfgPath := genSubCmd.String("config", "/etc/whispera/config.yaml", "Path to config.yaml")

	genSubCmd.Parse(os.Args[2:])

	if *usersCSV == "" {
		fmt.Fprintln(os.Stderr, "whispera generate-sub -users <user1,user2,...> [-name <name>] [-config <path>]")
		os.Exit(1)
	}
	if *name == "" {
		*name = fmt.Sprintf("Sub-%d", time.Now().Unix())
	}

	usernames := strings.Split(*usersCSV, ",")
	for i := range usernames {
		usernames[i] = strings.TrimSpace(usernames[i])
	}

	cfgProvider, err := config.New(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if err := cfgProvider.Load(*cfgPath); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load %s: %v\n", *cfgPath, err)
		os.Exit(1)
	}
	sc := cfgProvider.GetConfig()

	token, err := apiserver.CLICreateSubscription(*name, usernames)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create subscription: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Subscription %q created for %d user(s)\n", *name, len(usernames))

	serverHost := strings.TrimRight(sc.Server.PublicURL, "/")
	if serverHost == "" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		ip, _ := ipdetect.DetectServerIP(ctx)
		cancel()
		if ip == "" {
			ip = "<server_ip>"
		}
		serverHost = fmt.Sprintf("http://%s:8081", ip)
	}

	fmt.Println()
	fmt.Println("=== Subscription URL ===")
	fmt.Printf("%s/sub/%s\n", serverHost, token)
	fmt.Println()
	fmt.Println("Restart the whispera server for the new subscription to take effect.")
	os.Exit(0)
}

func RunViewKeysCmd() {
	viewKeysCmd := flag.NewFlagSet("view-keys", flag.ExitOnError)
	filterUser := viewKeysCmd.String("user", "", "Show only this user")
	full := viewKeysCmd.Bool("full", false, "Print the full whispera:// connection key")

	viewKeysCmd.Parse(os.Args[2:])

	users := apiserver.CLIListUsers()
	if len(users) == 0 {
		fmt.Println("No users found in /etc/whispera/users.json")
		os.Exit(0)
	}

	printed := 0
	for _, u := range users {
		if *filterUser != "" && u.Username != *filterUser {
			continue
		}
		printed++

		fmt.Printf("ID:      %d\n", u.ID)
		fmt.Printf("User:    %s\n", u.Username)
		fmt.Printf("Status:  %s\n", u.Status)
		fmt.Printf("Traffic: %d / %d bytes\n", u.Upload+u.Download, u.TrafficLimit)
		fmt.Printf("Created: %s\n", u.CreatedAt.Format(time.RFC3339))
		if u.ExpiryDate != "" {
			fmt.Printf("Expires: %s\n", u.ExpiryDate)
		}
		switch {
		case u.ConnectionURI == "":
			fmt.Println("Key:     (none — run create-key again to generate one)")
		case *full:
			fmt.Printf("Key:     %s\n", u.ConnectionURI)
		default:
			fmt.Printf("Key:     %s... (%d chars total, use -full to print)\n",
				u.ConnectionURI[:min(40, len(u.ConnectionURI))], len(u.ConnectionURI))
		}
		fmt.Println()
	}

	if *filterUser != "" && printed == 0 {
		fmt.Fprintf(os.Stderr, "User %q not found\n", *filterUser)
		os.Exit(1)
	}
	os.Exit(0)
}

func RunHashPasswordCmd() {
	if len(os.Args) < 3 || os.Args[2] == "" {
		fmt.Fprintln(os.Stderr, "Usage: whispera hash-password <password>")
		os.Exit(1)
	}
	h, err := bcrypt.GenerateFromPassword([]byte(os.Args[2]), bcrypt.DefaultCost)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(string(h))
	os.Exit(0)
}

func RunUpdateChecksumCmd() {
	cfgPath := "/etc/whispera/config.yaml"
	if len(os.Args) >= 3 {
		cfgPath = os.Args[2]
	}
	p, err := config.New(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if err := p.UpdateChecksum(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to update checksum: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Checksum updated successfully")
	os.Exit(0)
}
