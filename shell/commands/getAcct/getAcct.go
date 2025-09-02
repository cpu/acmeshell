package getAcct

import (
	"encoding/json"
	"net/http"

	"github.com/abiosoft/ishell"
	"github.com/cpu/acmeshell/acme"
	acmeclient "github.com/cpu/acmeshell/acme/client"
	"github.com/cpu/acmeshell/shell/commands"
)

func init() {
	commands.RegisterCommand(
		&ishell.Cmd{
			Name:     "getAccount",
			Aliases:  []string{"account", "getAcct", "registration", "getReg", "getRegistration"},
			Help:     "Get ACME account details from server",
			LongHelp: `TODO(@cpu): Write this!`,
			Func:     getAccountHandler,
		},
		nil)
}

func getAccountHandler(c *ishell.Context) {
	client := commands.GetClient(c)

	getAcctReq := struct {
		OnlyReturnExisting bool `json:"onlyReturnExisting"`
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

	signResult, err := client.Sign(newAcctURL, reqBody, &acmeclient.SigningOptions{
		EmbedKey: true,
	})
	if err != nil {
		c.Printf("getAccount: %s\n", err)
		return
	}

	resp, err := client.PostURL(newAcctURL, signResult.SerializedJWS)
	if err != nil {
		c.Printf("getAccount: failed to POST newAccount: %v\n", err)
		return
	}

	respOb := resp.Response
	if respOb.StatusCode != http.StatusOK {
		c.Printf("getAccount: failed to POST newAccount. Status code: %d\n", respOb.StatusCode)
		c.Printf("getAccount: response body: %s\n", resp.RespBody)
		return
	}

	c.Printf("%s\n", resp.RespBody)
}
