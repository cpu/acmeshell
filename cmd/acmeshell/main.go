package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/abiosoft/ishell"
	"github.com/abiosoft/readline"
	"github.com/cpu/acmeshell/acme"
	"github.com/cpu/acmeshell/cmd"
	acmeshell "github.com/cpu/acmeshell/shell"
	"github.com/letsencrypt/boulder/test/challtestsrv"
)

const (
	DIRECTORY_DEFAULT    = "https://acme-staging-v02.api.letsencrypt.org/directory"
	CA_DEFAULT           = "/etc/ssl/cert.pem"
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
		CA_DEFAULT,
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

	flag.Parse()

	if *pebble {
		pebbleDirectory := "https://localhost:14000/dir"
		directory = &pebbleDirectory
		pebbleBaseDir := os.Getenv("GOPATH")
		pebbleCA := pebbleBaseDir + "/src/github.com/letsencrypt/pebble/test/certs/pebble.minica.pem"
		caCert = &pebbleCA
	}

	// TODO(@cpu): There should be an acmeshell that does this crap all at once

	// Create an interactive shell
	shell := ishell.NewWithConfig(&readline.Config{
		Prompt: acmeshell.BasePrompt,
	})

	challSrv, err := challtestsrv.New(challtestsrv.Config{
		HTTPOneAddrs:    []string{fmt.Sprintf(":%d", *httpPort)},
		TLSALPNOneAddrs: []string{fmt.Sprintf(":%d", *tlsPort)},
		DNSOneAddrs:     []string{fmt.Sprintf(":%d", *dnsPort)},
		Log:             log.New(os.Stdout, "", log.Ldate|log.Ltime),
	})
	cmd.FailOnError(err, "Unable to create challenge test server")
	// Stash the challenge server in the shell for commands to access
	shell.Set(acmeshell.ChallSrvKey, challSrv)

	go challSrv.Run()

	// Create an ACME client
	client, err := acme.NewClient(acme.ClientConfig{
		DirectoryURL: *directory,
		CACert:       *caCert,
		AutoRegister: *autoRegister,
		AccountPath:  *acctPath,
		ContactEmail: *email,
	})
	cmd.FailOnError(err, "Unable to create ACME client")

	// Stash the ACME client in the shell for commands to access
	shell.Set(acmeshell.ClientKey, client)

	// Add all of the ACME shell's commands
	for _, cmd := range acmeshell.Commands {
		shell.AddCmd(cmd.New(client))
	}

	shell.Println("Welcome to ACME Shell")
	shell.Run()
	shell.Println("Goodbye!")
	challSrv.Shutdown()
}
