// The acmeshell command line tool provides a developer-oriented command-line
// shell interface for interacting with an ACME server.
package main

import (
	"flag"
	"fmt"
	"os"
	"syscall"

	acmeclient "github.com/cpu/acmeshell/acme/client"
	acmecmd "github.com/cpu/acmeshell/cmd"
	acmeshell "github.com/cpu/acmeshell/shell"
)

const (
	DIRECTORY_DEFAULT    = "https://acme-staging-v02.api.letsencrypt.org/directory"
	AUTOREGISTER_DEFAULT = true
	CONTACT_DEFAULT      = ""
	ACCOUNT_DEFAULT      = ""
	HTTP_PORT_DEFAULT    = 5002
	TLS_PORT_DEFAULT     = 5001
	DNS_PORT_DEFAULT     = 5252
)

func main() {
	directory := flag.String(
		"directory",
		DIRECTORY_DEFAULT,
		"Directory URL for ACME server")

	caCert := flag.String(
		"ca",
		"",
		"CA certificate(s) for verifying ACME server HTTPS")

	autoRegister := flag.Bool(
		"autoregister",
		AUTOREGISTER_DEFAULT,
		"Create an ACME account automatically at startup if required")

	email := flag.String(
		"contact",
		CONTACT_DEFAULT,
		"Optional contact email address for auto-registered ACME account")

	acctPath := flag.String(
		"account",
		ACCOUNT_DEFAULT,
		"Optional JSON filepath to save/restore auto-registered ACME account to")

	httpPort := flag.Int(
		"httpPort",
		HTTP_PORT_DEFAULT,
		"HTTP-01 challenge server port")

	tlsPort := flag.Int(
		"tlsPort",
		TLS_PORT_DEFAULT,
		"TLS-ALPN-01 challenge server port")

	dnsPort := flag.Int(
		"dnsPort",
		DNS_PORT_DEFAULT,
		"DNS-01 challenge server port")

	pebble := flag.Bool(
		"pebble",
		false,
		"Use Pebble defaults")

	printRequests := flag.Bool(
		"printRequests",
		false,
		"Print all HTTP requests to stdout")

	printResponses := flag.Bool(
		"printResponses",
		false,
		"Print all HTTP responses to stdout")

	printSignedData := flag.Bool(
		"printSignedData",
		false,
		"Print request data to stdout before signing")

	printJWS := flag.Bool(
		"printJWS",
		false,
		"Print all JWS in serialized form to stdout")

	commandFile := flag.String(
		"in",
		"",
		"Read commands from the specified file instead of stdin")

	postAsGet := flag.Bool(
		"postAsGet",
		false,
		"Use POST-as-GET requests instead of GET requests (requires Pebble -strict or equiv)")

	flag.Parse()

	if *pebble {
		pebbleDirectory := "https://localhost:14000/dir"
		directory = &pebbleDirectory
		pebbleBaseDir := os.Getenv("GOPATH")
		pebbleCA := pebbleBaseDir + "/src/github.com/letsencrypt/pebble/test/certs/pebble.minica.pem"
		caCert = &pebbleCA
	}

	if *commandFile != "" {
		f, err := os.Open(*commandFile)
		acmecmd.FailOnError(err, fmt.Sprintf(
			"Error opening -in file %q: %v", *commandFile, err))
		defer f.Close()
		err = syscall.Dup2(int(f.Fd()), 0)
		acmecmd.FailOnError(err, fmt.Sprintf(
			"Error duplicating stdin fd: %v", err))
	}

	config := &acmeshell.ACMEShellOptions{
		ClientConfig: acmeclient.ClientConfig{
			DirectoryURL: *directory,
			CACert:       *caCert,
			ContactEmail: *email,
			AccountPath:  *acctPath,
			AutoRegister: *autoRegister,
			POSTAsGET:    *postAsGet,
			InitialOutput: acmeclient.OutputOptions{
				PrintRequests:   *printRequests,
				PrintResponses:  *printResponses,
				PrintSignedData: *printSignedData,
				PrintJWS:        *printJWS,
			},
		},
		HTTPPort: *httpPort,
		TLSPort:  *tlsPort,
		DNSPort:  *dnsPort,
	}

	shell := acmeshell.NewACMEShell(config)
	shell.Run()
}
