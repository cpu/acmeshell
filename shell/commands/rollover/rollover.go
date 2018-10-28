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
	"github.com/cpu/acmeshell/shell/commands"
)

type keyRolloverOptions struct {
	printInnerJWS     bool
	printInnerJWSBody bool
	keyID             string
}

var (
	opts = keyRolloverOptions{}
)

func init() {
	registerRolloverCmd()
}

func registerRolloverCmd() {
	keyRolloverFlags := flag.NewFlagSet("keyRollover", flag.ContinueOnError)
	keyRolloverFlags.BoolVar(&opts.printInnerJWS, "innerJWS", false, "Print inner JWS JSON")
	keyRolloverFlags.BoolVar(&opts.printInnerJWSBody, "innerJWSBody", false, "Print inner JWS body JSON")
	keyRolloverFlags.StringVar(&opts.keyID, "keyID", "", "Key ID to rollover to (leave empty to select interactively)")

	commands.RegisterCommand(
		&ishell.Cmd{
			Name:     "rollover",
			Aliases:  []string{"keyRollover", "keyChange", "switchKey"},
			Help:     "Switch active account's key to a different key",
			LongHelp: `TODO`,
		},
		nil,
		rolloverHandler,
		keyRolloverFlags)
}

func rolloverHandler(c *ishell.Context, leftovers []string) {
	defer func() {
		opts = keyRolloverOptions{}
	}()

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
		if k, found := client.Keys[opts.keyID]; found {
			newKey = k
		}
		if newKey == nil {
			c.Printf("No key with ID %q known to shell\n", opts.keyID)
			return
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

	innerSignOpts := &acmeclient.SigningOptions{
		Key:      newKey,
		EmbedKey: true,
	}

	innerSignResult, err := client.Sign(targetURL, rolloverRequestJSON, innerSignOpts)
	if err != nil {
		c.Printf("keyRollover: error signing inner JWS: %s\n", err.Error())
		return
	}

	outerSignResult, err := client.Sign(targetURL, innerSignResult.SerializedJWS, nil)
	if err != nil {
		c.Printf("keyRollover: error signing outer JWS: %s\n", err.Error())
		return
	}

	c.Printf("Rolling over account %q to use specified key\n", account.ID)
	resp, err := client.PostURL(targetURL, outerSignResult.SerializedJWS)
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
