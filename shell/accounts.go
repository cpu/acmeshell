package shell

import (
	"flag"
	"strings"

	"github.com/abiosoft/ishell"
	"github.com/cpu/acmeshell/acme"
)

type accountsCmd struct {
	cmd *ishell.Cmd
}

type accountsOptions struct {
	printID      bool
	printContact bool
}

var Accounts accountsCmd = accountsCmd{
	cmd: &ishell.Cmd{
		Name: "accounts",
		Func: accountsHandler,
		Help: "Show available ACME accounts",
		LongHelp: `
	accounts:
		List the ACME accounts that have been created during the shell session. Each
		account's ID and contact information will be printed.

	accounts -showID=false:
		List ACME accounts printing only each account's contact info.
	
	accounts -showContact=false:
		List ACME accounts printing only each account's ID.`,
	},
}

func (a accountsCmd) New(client *acme.Client) *ishell.Cmd {
	return Accounts.cmd
}

func accountsHandler(c *ishell.Context) {
	opts := accountsOptions{}
	accountsFlags := flag.NewFlagSet("accounts", flag.ContinueOnError)
	accountsFlags.BoolVar(&opts.printID, "showID", true, "Print ACME account IDs")
	accountsFlags.BoolVar(&opts.printContact, "showContact", true, "Print ACME account contact info")

	err := accountsFlags.Parse(c.Args)
	if err != nil && err != flag.ErrHelp {
		c.Printf("accounts: error parsing input flags: %s\n", err.Error())
		return
	} else if err == flag.ErrHelp {
		return
	}

	if !opts.printID && !opts.printContact {
		c.Printf("accounts: -showID and -showContact can not both be false\n")
		return
	}

	client := getClient(c)

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
