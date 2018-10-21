// Package shell provides an interactive command shell and the associated
// acmeshell commands.
package shell

import (
	"fmt"
	"log"
	"net/url"
	"os"

	"github.com/abiosoft/ishell"
	"github.com/abiosoft/readline"
	acmeclient "github.com/cpu/acmeshell/acme/client"
	"github.com/cpu/acmeshell/challtestsrv"
	"github.com/cpu/acmeshell/cmd"
)

const (
	// The base prompt used for the ishell instance.
	BasePrompt = "[ ACME ] > "
	// The ishell context key that we store a client instance under.
	clientKey = "client"
	// The ishell context key that we store a challenge response server instance
	// under.
	challSrvKey = "challsrv"
)

var commands []AcmeCmd = []AcmeCmd{
	get,
	// TODO: Make all of this junk unexported
	Post,
	Accounts,
	NewAccount,
	LoadAccount,
	SwitchAccount,
	NewOrder,
	Orders,
	sign,
	CSR,
	viewKey,
	newKey,
	loadKey,
	keyRollover,
	poll,
	solve,
	finalize,
	getOrder,
	getAuthz,
	getChall,
	getCert,
	getAccount,
	echo,
	challSrv,
}

// TODO(@cpu): Rename this to ACMEShellCmd or something better than AcmeCmd.
type AcmeCmd interface {
	New(client *acmeclient.Client) *ishell.Cmd
}

// ACMEShellOptions allows specifying options for creating an ACME shell. This includes
// all of the acmeclient.ClientConfig options in addition challenge server
// response ports for HTTP-01, TLS-ALPN-01 and DNS-01 challenges.
type ACMEShellOptions struct {
	acmeclient.ClientConfig
	// Port number the ACME server validates HTTP-01 challenges over.
	HTTPPort int
	// Port number the ACME server validates TLS-ALPN-01 challenges over.
	TLSPort int
	// Port number the ACME server validates DNS-01 challenges over.
	DNSPort int
}

// ACMEShell is an ishell.Shell instance tailored for ACME. At its core an
// ACMEShell is a github.com/cpu/acmeshell/acme/client.Client instance with an
// associated github.com/cpu/acmeshell/challtestsrv.ChallengeTestSrv instance.
type ACMEShell struct {
	*ishell.Shell
}

// NewACMEShell creates an ACMEShell instance by building an *ishell.Shell
// instance, a *challtestsrv.ChallengeTestSrv instance, and
// a *acme/client.Client instance. The latter two are stored in the shell
// instance for access by commands. Important: The *ACMEShell and its associated
// challenge test server will not be started until the Run() function of the
// ACMEShell instance is called.
func NewACMEShell(opts *ACMEShellOptions) *ACMEShell {
	// Create an interactive shell
	shell := ishell.NewWithConfig(&readline.Config{
		// The base prompt used for the ishell instance.
		Prompt: BasePrompt,
	})

	// Create a challenge response server
	challSrv, err := challtestsrv.New(challtestsrv.Config{
		HTTPOneAddrs:    []string{fmt.Sprintf(":%d", opts.HTTPPort)},
		TLSALPNOneAddrs: []string{fmt.Sprintf(":%d", opts.TLSPort)},
		DNSOneAddrs:     []string{fmt.Sprintf(":%d", opts.DNSPort)},
		Log:             log.New(os.Stdout, "challRespSrv: ", log.Ldate|log.Ltime),
	})
	cmd.FailOnError(err, "Unable to create challenge test server")
	// Stash the challenge server in the shell for commands to access
	shell.Set(challSrvKey, challSrv)

	// Create an ACME client
	client, err := acmeclient.NewClient(opts.ClientConfig)
	cmd.FailOnError(err, "Unable to create ACME client")

	// Stash the ACME client in the shell for commands to access
	shell.Set(clientKey, client)

	// Add all of the ACMEShell commands
	for _, cmd := range commands {
		shell.AddCmd(cmd.New(client))
	}

	return &ACMEShell{
		Shell: shell,
	}
}

// Run starts the ACMEShell, dropping into an interactive session that blocks
// on user input until it is time to exit. The ACMEShell's challenge server will
// be started before starting the shell, and shut down after the shell session
// ends.
func (shell *ACMEShell) Run() {
	// Start the challenge server
	challSrv := getChallSrv(shell)
	go challSrv.Run()

	shell.Println("Welcome to ACME Shell")
	shell.Shell.Run()
	shell.Println("Goodbye!")
	challSrv.Shutdown()
}

// shellContext is a common interface that can be used to retrieve objects from
// a ishell.Shell or an ishell.Context.
type shellContext interface {
	Get(string) interface{}
}

// getClient reads a *acmeclient.Client from the shellContext or panics.
func getClient(c shellContext) *acmeclient.Client {
	if c.Get(clientKey) == nil {
		panic(fmt.Sprintf("nil %q value in shellContext", clientKey))
	}

	rawClient := c.Get(clientKey)
	switch c := rawClient.(type) {
	case *acmeclient.Client:
		return c
	}

	panic(fmt.Sprintf(
		"%q value in shellContext was not an *acmeclient.Client",
		clientKey))
}

// getChallSrv reads a *challtestsrv.ChallSrv from the shellContext or panics.
func getChallSrv(c shellContext) *challtestsrv.ChallSrv {
	if c.Get(challSrvKey) == nil {
		panic(fmt.Sprintf("nil %q value in shellContext", challSrvKey))
	}

	rawSrv := c.Get(challSrvKey)
	switch c := rawSrv.(type) {
	case *challtestsrv.ChallSrv:
		return c
	}

	panic(fmt.Sprintf(
		"%q value in shellContext was not a *challtestsrv.ChallSrv",
		challSrvKey))
}

func okURL(urlStr string) bool {
	result, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	if result.Scheme != "http" && result.Scheme != "https" {
		return false
	}
	return true
}

func directoryKeyCompleter(
	directory map[string]interface{},
	extra []string) func([]string) []string {
	// Copy the directory map keys into an array of strings
	dirKeys := make([]string, len(directory))
	i := 0
	for key := range directory {
		dirKeys[i] = key
		i++
	}
	// Add the extra entries (if any)
	dirKeys = append(dirKeys, extra...)
	// Return a completer function for the directory keys + extras
	return func(args []string) []string {
		return dirKeys
	}
}
