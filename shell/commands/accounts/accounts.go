package shell

import (
	"flag"
	"strings"

	"github.com/abiosoft/ishell"
	"github.com/cpu/acmeshell/shell/commands"
)

type accountsOptions struct {
	printID      bool
	printContact bool
}

var (
	opts accountsOptions
)

const (
	longHelp = `
	accounts:
		List the ACME accounts that have been created during the shell session. Each
		account's ID and contact information will be printed.

	accounts -showID=false:
		List ACME accounts printing only each account's contact info.
	
	accounts -showContact=false:
		List ACME accounts printing only each account's ID.`
)

func init() {
	commands.RegisterCommand(
		&ishell.Cmd{
			Name:     "accounts",
			Help:     "Show available ACME accounts",
			LongHelp: longHelp,
		},
		nil,
		accountsHandler,
		nil)
}

func accountsHandler(c *ishell.Context, args []string) {
	opts := accountsOptions{}
	accountsFlags := flag.NewFlagSet("accounts", flag.ContinueOnError)
	accountsFlags.BoolVar(&opts.printID, "showID", true, "Print ACME account IDs")
	accountsFlags.BoolVar(&opts.printContact, "showContact", true, "Print ACME account contact info")

	if _, err := commands.ParseFlagSetArgs(args, accountsFlags); err != nil {
		return
	}

	if !opts.printID && !opts.printContact {
		c.Printf("accounts: -showID and -showContact can not both be false\n")
		return
	}

	client := commands.GetClient(c)
	if len(client.Accounts) == 0 {
		c.Printf("No accounts\n")
		return
	}

	for i, acct := range client.Accounts {
		active := " "
		if client.ActiveAccountID() == acct.ID {
			active = "*"
		}

		c.Printf("%s", active)
		c.Printf("%3d)", i)

		if opts.printContact {
			contacts := "none"
			if len(acct.Contact) > 0 {
				contacts = strings.Join(acct.Contact, ", ")
			}
			c.Printf(" %s", contacts)
		}

		if opts.printID {
			c.Printf(" %q", acct.ID)
		}

		c.Printf("\n")
	}
}
