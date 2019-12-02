package rollover

import (
	"crypto"
	"flag"
	"sort"

	"github.com/abiosoft/ishell"
	"github.com/cpu/acmeshell/shell/commands"
)

func init() {
	commands.RegisterCommand(
		&ishell.Cmd{
			Name:     "rollover",
			Aliases:  []string{"keyRollover", "keyChange", "switchKey"},
			Help:     "Switch active account's key to a different key",
			LongHelp: `TODO`,
			Func:     rolloverHandler,
		},
		nil)
}

type keyRolloverOptions struct {
	keyID string
}

func rolloverHandler(c *ishell.Context) {
	opts := keyRolloverOptions{}
	keyRolloverFlags := flag.NewFlagSet("keyRollover", flag.ContinueOnError)
	keyRolloverFlags.StringVar(&opts.keyID, "keyID", "", "Key ID to rollover to (leave empty to select interactively)")

	if _, err := commands.ParseFlagSetArgs(c.Args, keyRolloverFlags); err != nil {
		return
	}

	client := commands.GetClient(c)

	if len(client.Keys) == 0 {
		c.Printf("No keys known to shell to rollover to\n")
		return
	}
	if len(client.Keys) == 1 {
		c.Printf("Only the active key is known to the shell. No other key to rollover to\n")
		return
	}

	var newKey crypto.Signer
	if opts.keyID == "" {
		var keysList []string
		for k := range client.Keys {
			// Skip the active key
			if k == client.ActiveAccountID() {
				continue
			}
			keysList = append(keysList, k)
		}
		sort.Strings(keysList)

		choice := c.MultiChoice(keysList, "Which key would you like to rollover to? ")
		newKey = client.Keys[keysList[choice]]
	} else {
		if k, found := client.Keys[opts.keyID]; found {
			newKey = k
		}
		if newKey == nil {
			c.Printf("No key with ID %q known to shell\n", opts.keyID)
			return
		}
	}

	if err := client.Rollover(newKey); err != nil {
		c.Printf("keyRollover: %v\n", err)
	}
}
