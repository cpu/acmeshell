package shell

import (
	"flag"
	"strings"

	"github.com/abiosoft/ishell"
	"github.com/cpu/acmeshell/acme"
)

type loadAccountCmd struct {
	cmd *ishell.Cmd
}

type loadAccountOptions struct {
	switchTo bool
	jsonPath string
}

var LoadAccount loadAccountCmd = loadAccountCmd{
	cmd: &ishell.Cmd{
		Name:     "loadAccount",
		Aliases:  []string{"loadAcct", "loadReg", "loadRegistration"},
		Func:     loadAccountHandler,
		Help:     "Load an existing ACME account from JSON",
		LongHelp: `TODO(@cpu): Write this!`,
	},
}

func (a loadAccountCmd) New(client *acme.Client) *ishell.Cmd {
	return LoadAccount.cmd
}

func loadAccountHandler(c *ishell.Context) {
	opts := loadAccountOptions{}
	loadAccountFlags := flag.NewFlagSet("loadAccount", flag.ContinueOnError)
	loadAccountFlags.BoolVar(&opts.switchTo, "switch", true, "Switch to the account after loading it")

	err := loadAccountFlags.Parse(c.Args)
	if err != nil && err != flag.ErrHelp {
		c.Printf("loadAccount: error parsing input flags: %s\n", err.Error())
		return
	} else if err == flag.ErrHelp {
		return
	}

	if loadAccountFlags.NArg() != 1 {
		c.Printf("loadAccount: you must specify a JSON filepath to load from\n")
		return
	}

	argument := strings.TrimSpace(loadAccountFlags.Arg(0))
	client := getClient(c)

	acct, err := acme.RestoreAccount(argument)
	if err != nil {
		c.Printf("loadAccount: error restoring account from %q : %s\n",
			argument, err)
		return
	}

	// TODO(@cpu): Maintain a map of account IDs to avoid this o(n) check
	for i, existingAcct := range client.Accounts {
		if acct.ID == existingAcct.ID {
			c.Printf("loadAccount: %q is already loaded as account # %d\n", argument, i)
			return
		}
	}

	c.Printf("Restored private key %q\n", acct.ID)
	client.Keys[acct.ID] = acct.PrivateKey

	c.Printf("Restored account with ID %q (Contact %s)\n",
		acct.ID, acct.Contact)
	client.Accounts = append(client.Accounts, acct)

	if opts.switchTo {
		// use the new account immediately
		client.ActiveAccount = acct
		c.Printf("Active account is now %q\n", client.ActiveAccount.ID)
	}
}
