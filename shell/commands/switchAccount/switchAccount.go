package switchAccount

import (
	"flag"
	"fmt"
	"strings"

	"github.com/abiosoft/ishell"
	"github.com/cpu/acmeshell/shell/commands"
)

var (
	opts = switchAccountOptions{}
)

func init() {
	commands.RegisterCommand(
		&ishell.Cmd{
			Name:     "switchAccount",
			Aliases:  []string{"switch", "switchAcct", "switchReg", "switchRegistration"},
			Help:     "Switch the active ACME account",
			LongHelp: `TODO(@cpu): Write this!`,
		},
		nil,
		switchAccountHandler,
		nil)
}

type switchAccountOptions struct {
	accountIndex int
}

func switchAccountHandler(c *ishell.Context, args []string) {
	opts := switchAccountOptions{}
	switchAccountFlags := flag.NewFlagSet("switchAccount", flag.ContinueOnError)
	switchAccountFlags.IntVar(&opts.accountIndex, "account", -1, "account number to switch to. leave blank to pick interactively")

	if _, err := commands.ParseFlagSetArgs(args, switchAccountFlags); err != nil {
		return
	}

	client := commands.GetClient(c)

	if opts.accountIndex >= 0 {
		if opts.accountIndex >= len(client.Accounts) {
			c.Printf("switchAccount: provided account index (%d) "+
				"is larger than number of accounts (%d)\n",
				opts.accountIndex, len(client.Accounts))
			return
		}

		client.ActiveAccount = client.Accounts[opts.accountIndex]
		c.Printf("Active account is now #%d - %q\n", opts.accountIndex, client.ActiveAccount.ID)
		return
	}

	accountList := make([]string, len(client.Accounts))
	for i, acct := range client.Accounts {
		line := fmt.Sprintf("%3d)", i)

		contacts := "none"
		if len(acct.Contact) > 0 {
			contacts = strings.Join(acct.Contact, ", ")
		}
		line += fmt.Sprintf(" %s", contacts)
		line += fmt.Sprintf(" %q", acct.ID)
		accountList[i] = line
	}

	choice := c.MultiChoice(accountList, "Which account would you like to switch to?")

	client.ActiveAccount = client.Accounts[choice]
	c.Printf("Active account is now #%d - %q\n", choice, client.ActiveAccount.ID)
}
