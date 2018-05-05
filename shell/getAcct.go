package shell

import (
	"encoding/json"
	"flag"
	"net/http"

	"github.com/abiosoft/ishell"
	"github.com/cpu/acmeshell/acme"
)

type getAccountOptions struct {
	acme.HTTPOptions
}

type getAccountCmd struct {
	cmd *ishell.Cmd
}

var getAccount getAccountCmd = getAccountCmd{
	cmd: &ishell.Cmd{
		Name:     "getAccount",
		Aliases:  []string{"account", "getAcct", "registration", "getReg", "getRegistration"},
		Func:     getAccountHandler,
		Help:     "Get ACME account details from server",
		LongHelp: `TODO(@cpu): Write this!`,
	},
}

func (g getAccountCmd) New(client *acme.Client) *ishell.Cmd {
	return getAccount.cmd
}

func getAccountHandler(c *ishell.Context) {
	opts := getAccountOptions{}
	getAccountFlags := flag.NewFlagSet("getAccount", flag.ContinueOnError)
	getAccountFlags.BoolVar(&opts.PrintHeaders, "headers", false, "Print HTTP response headers")
	getAccountFlags.BoolVar(&opts.PrintStatus, "status", true, "Print HTTP response status code")
	getAccountFlags.BoolVar(&opts.PrintResponse, "response", true, "Print HTTP response body")

	err := getAccountFlags.Parse(c.Args)
	if err != nil && err != flag.ErrHelp {
		c.Printf("getAccount: error parsing input flags: %s\n", err.Error())
		return
	} else if err == flag.ErrHelp {
		return
	}

	client := getClient(c)

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

	signedBody, err := client.ActiveAccount.Sign(newAcctURL, reqBody, acme.SignOptions{
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
