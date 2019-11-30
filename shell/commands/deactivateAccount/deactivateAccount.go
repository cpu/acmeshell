package deactivateAccount

import (
	"flag"
	"net/http"

	"github.com/abiosoft/ishell"
	"github.com/cpu/acmeshell/acme/resources"
	"github.com/cpu/acmeshell/shell/commands"
)

func init() {
	commands.RegisterCommand(
		&ishell.Cmd{
			Name:     "deactivateAccount",
			Aliases:  []string{"deactivateAcct"},
			Help:     "TODO: Describe the deactivateAccount command",
			LongHelp: "TODO: Describe the deactivateAccount command (long)",
			Func:     deactivateAccountHandler,
		},
		nil)
}

type deactivateAcctOptions struct {
	accountIndex int
}

func deactivateAccountHandler(c *ishell.Context) {
	var opts deactivateAcctOptions
	deactivateAcctFlags := flag.NewFlagSet("deactivateAccount", flag.ContinueOnError)
	deactivateAcctFlags.IntVar(&opts.accountIndex, "account", -1, "account number to deactivate. Default: active account is deactivated")

	if _, err := commands.ParseFlagSetArgs(c.Args, deactivateAcctFlags); err != nil {
		return
	}

	client := commands.GetClient(c)

	var acct *resources.Account
	if opts.accountIndex >= 0 {
		if opts.accountIndex >= len(client.Accounts) {
			c.Printf("deactivateAccount: provided account index (%d) "+
				"is larger than number of accounts (%d)\n",
				opts.accountIndex, len(client.Accounts))
			return
		}

		acct = client.Accounts[opts.accountIndex]
	} else {
		if client.ActiveAccountID() == "" {
			c.Printf("deactivateAccount: no active account to deactivate and no -account arg\n")
			return
		}
		acct = client.ActiveAccount
	}

	if acct == nil {
		c.Printf("deactivateAccount: selected account was nil\n")
		return
	}

	targetURL := acct.ID
	updateMsg := `{ "status": "deactivated" }`
	signResult, err := client.Sign(targetURL, []byte(updateMsg), nil)
	if err != nil {
		c.Printf("deactivateAccount: failed to sign account update POST body: %v\n", err)
		return
	}

	resp, err := client.PostURL(targetURL, signResult.SerializedJWS)
	if err != nil {
		c.Printf("deactivateAccount: failed to POST account %q: %v\n", targetURL, err)
		return
	}
	respOb := resp.Response
	if respOb.StatusCode != http.StatusOK {
		c.Printf("deactivateAccount: failed to POST %q account. Status code: %d\n", targetURL, respOb.StatusCode)
		c.Printf("deactivateAccount: response body: %s\n", resp.RespBody)
		return
	}
	c.Printf("Account %q deactivated\n", targetURL)
}
