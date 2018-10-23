package getAcct

import (
	"encoding/json"
	"flag"
	"net/http"

	"github.com/abiosoft/ishell"
	"github.com/cpu/acmeshell/acme"
	acmeclient "github.com/cpu/acmeshell/acme/client"
	"github.com/cpu/acmeshell/acme/resources"
	"github.com/cpu/acmeshell/shell/commands"
)

type getAccountCmd struct {
	commands.BaseCmd
}

type getAccountOptions struct {
	acmeclient.HTTPOptions
}

var GetAccountCommand = getAccountCmd{
	commands.BaseCmd{
		Cmd: &ishell.Cmd{
			Name:     "getAccount",
			Aliases:  []string{"account", "getAcct", "registration", "getReg", "getRegistration"},
			Func:     getAccountHandler,
			Help:     "Get ACME account details from server",
			LongHelp: `TODO(@cpu): Write this!`,
		},
	},
}

func (g getAccountCmd) Setup(client *acmeclient.Client) (*ishell.Cmd, error) {
	return GetAccountCommand.Cmd, nil
}

func getAccountHandler(c *ishell.Context) {
	opts := getAccountOptions{}
	getAccountFlags := flag.NewFlagSet("getAccount", flag.ContinueOnError)
	err := getAccountFlags.Parse(c.Args)
	if err != nil && err != flag.ErrHelp {
		c.Printf("getAccount: error parsing input flags: %s\n", err.Error())
		return
	} else if err == flag.ErrHelp {
		return
	}

	client := commands.GetClient(c)

	getAcctReq := struct {
		OnlyReturnExisting bool
	}{
		OnlyReturnExisting: true,
	}
	reqBody, _ := json.Marshal(&getAcctReq)
	newAcctURL, ok := client.GetEndpointURL(acme.NEW_ACCOUNT_ENDPOINT)
	if !ok {
		c.Printf(
			"getAccount: ACME server missing %q endpoint in directory\n",
			acme.NEW_ACCOUNT_ENDPOINT)
		return
	}

	signedBody, err := client.ActiveAccount.Sign(newAcctURL, reqBody, resources.SignOptions{
		EmbedKey:    true,
		NonceSource: client,
	})
	if err != nil {
		c.Printf("getAccount: %s\n", err)
		return
	}

	respCtx := client.PostURL(newAcctURL, signedBody, &opts.HTTPOptions)
	if respCtx.Err != nil {
		c.Printf("getAccount: failed to POST newAccount: %s\n", respCtx.Err.Error())
		return
	}

	if respCtx.Resp.StatusCode != http.StatusOK {
		c.Printf("getAccount: failed to POST newAccount. Status code: %d\n", respCtx.Resp.StatusCode)
		c.Printf("getAccount: response body: %s\n", respCtx.Body)
		return
	}
}
