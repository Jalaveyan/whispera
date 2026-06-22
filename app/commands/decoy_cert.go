package commands

import (
	"flag"
	"fmt"
	"os"
	"time"
	"whispera/core/protocol"
)

func RunGenDecoyCertCmd() {
	genCmd := flag.NewFlagSet("gen-decoy-cert", flag.ExitOnError)
	domain := genCmd.String("domain", "", "Real-world domain to clone the certificate fields from (e.g. example.com)")
	outCert := genCmd.String("out-cert", "/etc/whispera/whispera.crt", "Output path for the generated certificate (PEM)")
	outKey := genCmd.String("out-key", "/etc/whispera/whispera.key", "Output path for the generated private key (PEM)")

	genCmd.Parse(os.Args[2:])

	if *domain == "" {
		fmt.Fprintln(os.Stderr, "whispera gen-decoy-cert -domain <real-domain> [-out-cert <path>] [-out-key <path>]")
		os.Exit(1)
	}

	info, err := protocol.CloneCertToFiles(*domain, *outCert, *outKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate decoy certificate: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Cloned certificate fields from %s\n", *domain)
	fmt.Printf("Subject:     %s\n", info.Subject)
	if len(info.DNSNames) > 0 {
		fmt.Printf("SAN (DNS):   %v\n", info.DNSNames)
	}
	fmt.Printf("Valid:       %s -> %s\n", info.NotBefore.Format(time.RFC3339), info.NotAfter.Format(time.RFC3339))
	fmt.Printf("Cert:        %s\n", *outCert)
	fmt.Printf("Key:         %s\n", *outKey)
	fmt.Println()
	fmt.Println("Set whispera.tls_cert / whispera.tls_key to these paths and restart the server.")
	os.Exit(0)
}
