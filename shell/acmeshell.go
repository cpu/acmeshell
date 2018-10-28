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
	accounts "github.com/cpu/acmeshell/shell/commands/accounts"
	challSrv "github.com/cpu/acmeshell/shell/commands/challSrv"
	//csr "github.com/cpu/acmeshell/shell/commands/csr"
	echo "github.com/cpu/acmeshell/shell/commands/echo"
	finalize "github.com/cpu/acmeshell/shell/commands/finalize"
	_ "github.com/cpu/acmeshell/shell/commands/get"
	getAcct "github.com/cpu/acmeshell/shell/commands/getAcct"
	getAuthz "github.com/cpu/acmeshell/shell/commands/getAuthz"
	getCert "github.com/cpu/acmeshell/shell/commands/getCert"
	getChall "github.com/cpu/acmeshell/shell/commands/getChall"
	getOrder "github.com/cpu/acmeshell/shell/commands/getOrder"
	keys "github.com/cpu/acmeshell/shell/commands/keys"
	loadAccount "github.com/cpu/acmeshell/shell/commands/loadAccount"
	loadKey "github.com/cpu/acmeshell/shell/commands/loadKey"
	newAccount "github.com/cpu/acmeshell/shell/commands/newAccount"
	newKey "github.com/cpu/acmeshell/shell/commands/newKey"
	newOrder "github.com/cpu/acmeshell/shell/commands/newOrder"
	orders "github.com/cpu/acmeshell/shell/commands/orders"
	_ "github.com/cpu/acmeshell/shell/commands/poll"
	_ "github.com/cpu/acmeshell/shell/commands/post"
	rollover "github.com/cpu/acmeshell/shell/commands/rollover"
	sign "github.com/cpu/acmeshell/shell/commands/sign"
	solve "github.com/cpu/acmeshell/shell/commands/solve"
	switchAccount "github.com/cpu/acmeshell/shell/commands/switchAccount"
)

var shellCommands = []commands.ACMEShellCmd{
	accounts.AccountsCommand,
	challSrv.ChallSrvCommand,
	// TODO(@cpu): Fix CSR command
	//csr.CSRCommand,
	finalize.FinalizeCommand,
	getAcct.GetAccountCommand,
	getAuthz.GetAuthzCommand,
	getCert.GetCertCommand,
	getChall.GetChallCommand,
	getOrder.GetOrderCommand,
	keys.KeysCommand,
	loadAccount.LoadAccountCommand,
	loadKey.LoadKeyCommand,
	newAccount.NewAccountCommand,
	newKey.NewKeyCommand,
	newOrder.NewOrderCommand,
	orders.OrdersCommand,
	rollover.RolloverCommand,
	sign.SignCommand,
	solve.SolveCommand,
	switchAccount.SwitchAccountCommand,
	echo.EchoCommand,
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

	// Add all of the ACMEShell commands
	// TODO(@cpu): Delete this junk
	for _, cmd := range shellCommands {
		shellCommand, err := cmd.Setup(client)
		acmecmd.FailOnError(err, fmt.Sprintf(
			"Unable to setup ACME command %T",
			cmd))
		shell.AddCmd(shellCommand)
	}

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
