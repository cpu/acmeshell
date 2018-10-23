package newAccount

import (
	"flag"
	"strings"

	"crypto/ecdsa"
	"github.com/abiosoft/ishell"
	acmeclient "github.com/cpu/acmeshell/acme/client"
	"github.com/cpu/acmeshell/acme/resources"
	"github.com/cpu/acmeshell/shell/commands"
)

type newAccountCmd struct {
	commands.BaseCmd
}

type newAccountOptions struct {
	acmeclient.HTTPPostOptions
	contacts string
	switchTo bool
	jsonPath string
	keyID    string
}

var NewAccountCommand = newAccountCmd{
	commands.BaseCmd{
		Cmd: &ishell.Cmd{
			Name:     "newAccount",
			Aliases:  []string{"newAcct", "newReg", "newRegistration"},
			Func:     newAccountHandler,
			Help:     "Create a new ACME account",
			LongHelp: `TODO(@cpu): Write this!`,
		},
	},
}

func (a newAccountCmd) Setup(client *acmeclient.Client) (*ishell.Cmd, error) {
	return NewAccountCommand.Cmd, nil
}

func newAccountHandler(c *ishell.Context) {
	opts := newAccountOptions{}
	newAccountFlags := flag.NewFlagSet("newAccount", flag.ContinueOnError)
	newAccountFlags.StringVar(&opts.contacts, "contacts", "", "Comma separated list of contact emails")
	newAccountFlags.BoolVar(&opts.switchTo, "switch", true, "Switch to the new account after creating it")
	newAccountFlags.StringVar(&opts.jsonPath, "json", "", "Optional filepath to a JSON save file for the account")
	newAccountFlags.StringVar(&opts.keyID, "keyID", "", "Key ID for existing key (empty to generate new key)")

	newAccountFlags.BoolVar(&opts.PrintJWS, "jwsBody", false, "Print JWS body before POSTing")
	newAccountFlags.BoolVar(&opts.PrintJWSObject, "jwsObj", false, "Print JWS object before POSTing")
	newAccountFlags.BoolVar(&opts.PrintJSON, "jsonBody", false, "Print JSON body before signing")

	err := newAccountFlags.Parse(c.Args)
	if err != nil && err != flag.ErrHelp {
		c.Printf("newAccount: error parsing input flags: %s\n", err.Error())
		return
	} else if err == flag.ErrHelp {
		return
	}

	rawEmails := strings.Split(opts.contacts, ",")
	var emails []string
	if len(rawEmails) > 1 {
		for _, e := range rawEmails {
			email := strings.TrimSpace(e)
			if email == "" {
				continue
			}
			// Remove mailto: if present - we add it ourselves
			email = strings.TrimPrefix(email, "mailto:")
			emails = append(emails, email)
		}
	}

	client := commands.GetClient(c)

	var acctKey *ecdsa.PrivateKey
	if opts.keyID != "" {
		if key, found := client.Keys[opts.keyID]; !found {
			c.Printf("newAccount: Key ID %q does not exist in shell\n", opts.keyID)
			return
		} else {
			acctKey = key
		}
	}
	acct, err := resources.NewAccount(emails, acctKey)
	if err != nil {
		c.Printf("newAccount: error creating new account object: %s\n", err)
		return
	}

	// create the account with the ACME server
	err = client.CreateAccount(acct, &opts.HTTPPostOptions)
	if err != nil {
		c.Printf("newAccount: error creating new account with ACME server: %s\n", err)
		return
	}
	// if opts.keyID was empty then resources.NewAccount got a nil key argument and
	// generated a new key on the fly. We need to save that key
	if opts.keyID == "" {
		client.Keys[acct.ID] = acct.PrivateKey
		c.Printf("Created private key for ID %q\n", acct.ID)
	}

	c.Printf("Created account with ID %q Contacts %q\n", acct.ID, acct.Contact)
	// store the account object
	client.Accounts = append(client.Accounts, acct)

	if opts.jsonPath != "" {
		err := resources.SaveAccount(opts.jsonPath, acct)
		if err != nil {
			c.Printf("error saving account to %q : %s\n", opts.jsonPath, err)
		}
		c.Printf("Saved account data to %q\n", opts.jsonPath)
	}

	if opts.switchTo {
		// use the new account immediately
		client.ActiveAccount = acct
		c.Printf("Active account is now %q\n", client.ActiveAccount.ID)
	}
}
