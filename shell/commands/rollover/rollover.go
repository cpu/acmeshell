package rollover

import (
	"crypto/ecdsa"
	"encoding/json"
	"flag"
	"net/http"
	"sort"

	jose "gopkg.in/square/go-jose.v2"

	"github.com/abiosoft/ishell"
	acmeclient "github.com/cpu/acmeshell/acme/client"
	"github.com/cpu/acmeshell/acme/resources"
	"github.com/cpu/acmeshell/shell/commands"
)

type keyRolloverCmd struct {
	commands.BaseCmd
}

type keyRolloverOptions struct {
	acmeclient.HTTPPostOptions
	printInnerJWS     bool
	printInnerJWSBody bool
	keyID             string
}

var RolloverCommand = keyRolloverCmd{
	commands.BaseCmd{
		Cmd: &ishell.Cmd{
			Name:     "rollover",
			Aliases:  []string{"keyRollover", "keyChange", "switchKey"},
			Func:     rolloverHandler,
			Help:     "Switch active account's key to a different key",
			LongHelp: `TODO`,
		},
	},
}

func (kr keyRolloverCmd) Setup(client *acmeclient.Client) (*ishell.Cmd, error) {
	return RolloverCommand.Cmd, nil
}

func rolloverHandler(c *ishell.Context) {
	opts := keyRolloverOptions{}
	keyRolloverFlags := flag.NewFlagSet("keyRollover", flag.ContinueOnError)
	keyRolloverFlags.BoolVar(&opts.printInnerJWS, "innerJWS", false, "Print inner JWS JSON")
	keyRolloverFlags.BoolVar(&opts.printInnerJWSBody, "innerJWSBody", false, "Print inner JWS body JSON")
	keyRolloverFlags.StringVar(&opts.keyID, "keyID", "", "Key ID to rollover to (leave empty to select interactively)")

	keyRolloverFlags.BoolVar(&opts.PrintJWS, "jwsBody", false, "Print JWS body before POSTing")
	keyRolloverFlags.BoolVar(&opts.PrintJWSObject, "jwsObj", false, "Print JWS object before POSTing")
	keyRolloverFlags.BoolVar(&opts.PrintJSON, "jsonBody", false, "Print JSON body before signing")

	err := keyRolloverFlags.Parse(c.Args)
	if err != nil && err != flag.ErrHelp {
		c.Printf("keyRollover: error parsing input flags: %s", err.Error())
		return
	} else if err == flag.ErrHelp {
		return
	}

	client := commands.GetClient(c)
	account := client.ActiveAccount

	if len(client.Keys) == 0 {
		c.Printf("No keys known to shell to rollover to\n")
		return
	}
	if len(client.Keys) == 1 {
		c.Printf("Only the active key is known to the shell. No other key to rollover to\n")
		return
	}

	if _, supported := client.GetEndpointURL("keyChange"); !supported {
		c.Printf("Server missing \"keyChange\" entry in directory. Key rollover unsupported.\n")
		return
	}

	targetURL, _ := client.GetEndpointURL("keyChange")

	var newKey *ecdsa.PrivateKey
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
		if k, found := client.Keys[opts.keyID]; !found {
			c.Printf("No key with ID %q known to shell\n", opts.keyID)
			return
		} else {
			newKey = k
		}
	}

	// TODO(@cpu): Most of this should be hoisted into a client Rollover function
	// that the command can use for the heavy lifting (ala the newAccount command
	// and the CreateAccount function).

	oldKey := jose.JSONWebKey{
		Key:       account.PrivateKey.Public(),
		Algorithm: "ECDSA",
	}

	rolloverRequest := struct {
		Account string
		OldKey  jose.JSONWebKey
	}{
		Account: account.ID,
		OldKey:  oldKey,
	}

	rolloverRequestJSON, err := json.Marshal(&rolloverRequest)
	if err != nil {
		c.Printf("keyRollover: failed to marshal rollover request to JSON: %s\n", err.Error())
		return
	}

	innerSignOpts := resources.SignOptions{
		NonceSource:    client,
		Key:            newKey,
		EmbedKey:       true,
		PrintJWS:       false,
		PrintJWSObject: false,
		PrintJSON:      opts.printInnerJWSBody,
	}

	innerJWS, err := account.Sign(targetURL, rolloverRequestJSON, innerSignOpts)
	if err != nil {
		c.Printf("keyRollover: error signing inner JWS: %s\n", err.Error())
		return
	}

	if opts.printInnerJWS {
		c.Printf("inner JWS:\n%s\n", string(innerJWS))
	}

	outerJWS, err := account.Sign(targetURL, innerJWS, resources.SignOptions{
		NonceSource:    client,
		PrintJWS:       false,
		PrintJWSObject: false,
		PrintJSON:      false,
	})
	if err != nil {
		c.Printf("keyRollover: error signing outer JWS: %s\n", err.Error())
		return
	}

	c.Printf("Rolling over account %q to use specified key\n", account.ID)
	resp, err := client.PostURL(targetURL, outerJWS, &opts.HTTPOptions)
	if err != nil {
		c.Printf("keyRollover: keyRollover POST failed: %v\n", err)
		return
	}

	respOb := resp.Response
	if respOb.StatusCode != http.StatusOK {
		c.Printf("keyRollover: keyRollover POST failed. Status code: %d\n", respOb.StatusCode)
		c.Printf("Response body: \n%s\n", resp.RespBody)
		return
	}

	client.Keys[account.ID] = newKey
	account.PrivateKey = newKey
	c.Printf("keyRollover for account %q completed\n", account.ID)
}
