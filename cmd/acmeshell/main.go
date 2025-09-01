// The acmeshell command line tool provides a developer-oriented command-line
// shell interface for interacting with an ACME server.
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	acmeclient "github.com/cpu/acmeshell/acme/client"
	acmecmd "github.com/cpu/acmeshell/cmd"
	acmeshell "github.com/cpu/acmeshell/shell"
)

const (
	DIRECTORY_DEFAULT    = "https://acme-staging-v02.api.letsencrypt.org/directory"
	AUTOREGISTER_DEFAULT = true
	CONTACT_DEFAULT      = ""
	ACCOUNT_DEFAULT      = "acmeshell.account.json"
	HTTP_PORT_DEFAULT    = 5002
	TLS_PORT_DEFAULT     = 5001
	DNS_PORT_DEFAULT     = 5252
	CHALLSRV_DEFAULT     = ""

	// PEBBLE_CA_DEFAULT is an embedded const version of
	// github.com/letsencrypt/pebble/test/certs/pebble.minica.pem
	// The -pebble command line flag will write this .pem to a tempfile to
	// reference.
	PEBBLE_CA_DEFAULT = `
-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIIJOLbes8sTr4wDQYJKoZIhvcNAQELBQAwIDEeMBwGA1UE
AxMVbWluaWNhIHJvb3QgY2EgMjRlMmRiMCAXDTE3MTIwNjE5NDIxMFoYDzIxMTcx
MjA2MTk0MjEwWjAgMR4wHAYDVQQDExVtaW5pY2Egcm9vdCBjYSAyNGUyZGIwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC5WgZNoVJandj43kkLyU50vzCZ
alozvdRo3OFiKoDtmqKPNWRNO2hC9AUNxTDJco51Yc42u/WV3fPbbhSznTiOOVtn
Ajm6iq4I5nZYltGGZetGDOQWr78y2gWY+SG078MuOO2hyDIiKtVc3xiXYA+8Hluu
9F8KbqSS1h55yxZ9b87eKR+B0zu2ahzBCIHKmKWgc6N13l7aDxxY3D6uq8gtJRU0
toumyLbdzGcupVvjbjDP11nl07RESDWBLG1/g3ktJvqIa4BWgU2HMh4rND6y8OD3
Hy3H8MY6CElL+MOCbFJjWqhtOxeFyZZV9q3kYnk9CAuQJKMEGuN4GU6tzhW1AgMB
AAGjRTBDMA4GA1UdDwEB/wQEAwIChDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYB
BQUHAwIwEgYDVR0TAQH/BAgwBgEB/wIBADANBgkqhkiG9w0BAQsFAAOCAQEAF85v
d40HK1ouDAtWeO1PbnWfGEmC5Xa478s9ddOd9Clvp2McYzNlAFfM7kdcj6xeiNhF
WPIfaGAi/QdURSL/6C1KsVDqlFBlTs9zYfh2g0UXGvJtj1maeih7zxFLvet+fqll
xseM4P9EVJaQxwuK/F78YBt0tCNfivC6JNZMgxKF59h0FBpH70ytUSHXdz7FKwix
Mfn3qEb9BXSk0Q3prNV5sOV3vgjEtB4THfDxSz9z3+DepVnW3vbbqwEbkXdk3j82
2muVldgOUgTwK8eT+XdofVdntzU/kzygSAtAQwLJfn51fS1GvEcYGBc1bDryIqmF
p9BI7gVKtWSZYegicA==
-----END CERTIFICATE-----
`
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
		"Optional JSON filepath to use to save/restore auto-registered ACME account")

	challSrv := flag.String(
		"challsrv",
		CHALLSRV_DEFAULT,
		"Optional API address for an external pebble-challtestsrv instance to use")

	httpPort := flag.Int(
		"httpPort",
		HTTP_PORT_DEFAULT,
		"HTTP-01 challenge server port for internal challtestsrv")

	tlsPort := flag.Int(
		"tlsPort",
		TLS_PORT_DEFAULT,
		"TLS-ALPN-01 challenge server port for internal challtestsrv")

	dnsPort := flag.Int(
		"dnsPort",
		DNS_PORT_DEFAULT,
		"DNS-01 challenge server port for internal challtestsrv")

	pebble := flag.Bool(
		"pebble",
		false,
		"Use Pebble defaults")

	printNonceUpdates := flag.Bool(
		"printNonces",
		false,
		"Print all nonce updates and HEAD requests")

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
		true,
		"Use POST-as-GET requests instead of GET requests in high level commands")

	flag.Parse()

	if *pebble {
		tmpFile, err := ioutil.TempFile("", "pebble.ca.*.pem")
		acmecmd.FailOnError(err, fmt.Sprintf("Error opening pebble CA temp file: %v", err))
		defer func() { _ = os.Remove(tmpFile.Name()) }()

		_, err = tmpFile.Write([]byte(PEBBLE_CA_DEFAULT))
		acmecmd.FailOnError(err, fmt.Sprintf("Error writing pebble CA temp file: %v", err))

		pebbleCA := tmpFile.Name()

		err = tmpFile.Close()
		acmecmd.FailOnError(err, fmt.Sprintf("Error closing pebble CA temp file: %v", err))

		pebbleDirectory := "https://localhost:14000/dir"
		pebbleChallSrv := "http://localhost:8055"
		directory = &pebbleDirectory
		caCert = &pebbleCA
		challSrv = &pebbleChallSrv
	}

	if *commandFile != "" {
		f, err := os.Open(*commandFile)
		acmecmd.FailOnError(err, fmt.Sprintf(
			"Error opening -in file %q: %v", *commandFile, err))
		defer func() { _ = f.Close() }()
		err = redirectStdin(int(f.Fd()))
		acmecmd.FailOnError(err, fmt.Sprintf(
			"Error redirecting stdin fd: %v", err))
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
				PrintRequests:     *printRequests,
				PrintResponses:    *printResponses,
				PrintSignedData:   *printSignedData,
				PrintJWS:          *printJWS,
				PrintNonceUpdates: *printNonceUpdates,
			},
		},
		ChallSrv: *challSrv,
		HTTPPort: *httpPort,
		TLSPort:  *tlsPort,
		DNSPort:  *dnsPort,
	}

	shell := acmeshell.NewACMEShell(config)
	shell.Run()
}
