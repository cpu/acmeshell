// Package shell provides an interactive command shell and the associated
// acmeshell commands.
package shell

import (
	"fmt"
	"log"
	"os"

	"github.com/abiosoft/ishell"
	"github.com/abiosoft/readline"
	acmeclient "github.com/cpu/acmeshell/acme/client"
	"github.com/cpu/acmeshell/challtestsrv"
	acmecmd "github.com/cpu/acmeshell/cmd"
	"github.com/cpu/acmeshell/shell/commands"
	_ "github.com/cpu/acmeshell/shell/commands/accounts"
	_ "github.com/cpu/acmeshell/shell/commands/challSrv"
	_ "github.com/cpu/acmeshell/shell/commands/csr"
	_ "github.com/cpu/acmeshell/shell/commands/echo"
	_ "github.com/cpu/acmeshell/shell/commands/finalize"
	_ "github.com/cpu/acmeshell/shell/commands/get"
	_ "github.com/cpu/acmeshell/shell/commands/getAcct"
	_ "github.com/cpu/acmeshell/shell/commands/getAuthz"
	_ "github.com/cpu/acmeshell/shell/commands/getCert"
	_ "github.com/cpu/acmeshell/shell/commands/getChall"
	_ "github.com/cpu/acmeshell/shell/commands/getOrder"
	_ "github.com/cpu/acmeshell/shell/commands/keys"
	_ "github.com/cpu/acmeshell/shell/commands/loadAccount"
	_ "github.com/cpu/acmeshell/shell/commands/loadKey"
	_ "github.com/cpu/acmeshell/shell/commands/newAccount"
	_ "github.com/cpu/acmeshell/shell/commands/newKey"
	_ "github.com/cpu/acmeshell/shell/commands/newOrder"
	_ "github.com/cpu/acmeshell/shell/commands/orders"
	_ "github.com/cpu/acmeshell/shell/commands/poll"
	_ "github.com/cpu/acmeshell/shell/commands/post"
	_ "github.com/cpu/acmeshell/shell/commands/rollover"
	_ "github.com/cpu/acmeshell/shell/commands/sign"
	_ "github.com/cpu/acmeshell/shell/commands/solve"
	_ "github.com/cpu/acmeshell/shell/commands/switchAccount"
)

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
		Prompt: commands.BasePrompt,
	})

	// Create a challenge response server
	challSrv, err := challtestsrv.New(challtestsrv.Config{
		HTTPOneAddrs:    []string{fmt.Sprintf(":%d", opts.HTTPPort)},
		TLSALPNOneAddrs: []string{fmt.Sprintf(":%d", opts.TLSPort)},
		DNSOneAddrs:     []string{fmt.Sprintf(":%d", opts.DNSPort)},
		Log:             log.New(os.Stdout, "challRespSrv: ", log.Ldate|log.Ltime),
	})
	acmecmd.FailOnError(err, "Unable to create challenge test server")
	// Stash the challenge server in the shell for commands to access
	shell.Set(commands.ChallSrvKey, challSrv)

	// Create an ACME client
	client, err := acmeclient.NewClient(opts.ClientConfig)
	acmecmd.FailOnError(err, "Unable to create ACME client")

	// Stash the ACME client in the shell for commands to access
	shell.Set(commands.ClientKey, client)

	// Add registered commands to the shell
	commands.AddCommands(shell, client)

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
	challSrv := commands.GetChallSrv(shell)
	go challSrv.Run()

	shell.Println("Welcome to ACME Shell")
	shell.Shell.Run()
	shell.Println("Goodbye!")
	challSrv.Shutdown()
}
