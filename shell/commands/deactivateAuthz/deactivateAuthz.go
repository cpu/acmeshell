package deactivateAuthz

import (
	"flag"
	"net/http"
	"strings"

	"github.com/abiosoft/ishell"
	"github.com/cpu/acmeshell/shell/commands"
)

func init() {
	commands.RegisterCommand(
		&ishell.Cmd{
			Name:     "deactivateAuthz",
			Aliases:  []string{"deactivateAuthorization"},
			Help:     "TODO: Describe the deactivateAuthz command",
			LongHelp: "TODO: Describe the deactivateAuthz command (long)",
			Func:     deactivateAuthzHandler,
		},
		nil)
}

type deactivateAuthzOptions struct {
	orderIndex int
	identifier string
}

func deactivateAuthzHandler(c *ishell.Context) {
	var opts deactivateAuthzOptions
	deactivateFlags := flag.NewFlagSet("deactivateAuthz", flag.ContinueOnError)
	deactivateFlags.IntVar(&opts.orderIndex, "order", -1, "index of existing order")
	deactivateFlags.StringVar(&opts.identifier, "identifier", "", "identifier of authorization")

	leftovers, err := commands.ParseFlagSetArgs(c.Args, deactivateFlags)
	if err != nil {
		return
	}

	if opts.orderIndex != -1 && len(leftovers) > 0 {
		c.Printf("-order can not be used with an authz URL\n")
		return
	}

	if opts.identifier != "" && len(leftovers) > 0 {
		c.Printf("-identifier can not be used with an authz URL\n")
		return
	}

	client := commands.GetClient(c)

	var targetURL string
	if len(leftovers) > 0 {
		templateText := strings.Join(leftovers, " ")
		targetURL, err = commands.ClientTemplate(client, templateText)
	} else {
		targetURL, err = commands.FindOrderURL(c, nil, opts.orderIndex)
		if err != nil {
			c.Printf("deactivateAuthz: error getting order URL: %v\n", err)
			return
		}
		targetURL, err = commands.FindAuthzURL(c, targetURL, opts.identifier)
	}

	if err != nil {
		c.Printf("deactivateAuthz: error getting authz URL: %v\n", err)
		return
	}
	if targetURL == "" {
		c.Printf("deactivateAuthz: target URL was empty\n")
		return
	}

	updateMsg := `{ "status": "deactivated" }`
	signResult, err := client.Sign(targetURL, []byte(updateMsg), nil)
	if err != nil {
		c.Printf("deactivateAuthz: failed to sign authz update POST body: %v\n", err)
		return
	}

	resp, err := client.PostURL(targetURL, signResult.SerializedJWS)
	if err != nil {
		c.Printf("deactivateAuthz: failed to POST challenge %q: %v\n", targetURL, err)
		return
	}
	respOb := resp.Response
	if respOb.StatusCode != http.StatusOK {
		c.Printf("deactivateAuthz: failed to POST %q authz. Status code: %d\n", targetURL, respOb.StatusCode)
		c.Printf("deactivateAuthz: response body: %s\n", resp.RespBody)
		return
	}
	c.Printf("Authz %q deactivated\n", targetURL)
}
