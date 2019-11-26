package getauthz

import (
	"flag"
	"strings"

	"github.com/abiosoft/ishell"
	"github.com/cpu/acmeshell/acme/resources"
	"github.com/cpu/acmeshell/shell/commands"
)

func init() {
	commands.RegisterCommand(
		&ishell.Cmd{
			Name:     "getAuthz",
			Aliases:  []string{"authz", "authorization"},
			Help:     "Get an ACME authz URL",
			LongHelp: `TODO(@cpu): Write this!`,
		},
		nil,
		getAuthzHandler,
		nil)
}

type getAuthzOptions struct {
	orderIndex int
	identifier string
}

func getAuthzHandler(c *ishell.Context, args []string) {
	opts := getAuthzOptions{}
	getAuthzFlags := flag.NewFlagSet("getAuthz", flag.ContinueOnError)
	getAuthzFlags.IntVar(&opts.orderIndex, "order", -1, "index of existing order")
	getAuthzFlags.StringVar(&opts.identifier, "identifier", "", "identifier of authorization")

	leftovers, err := commands.ParseFlagSetArgs(args, getAuthzFlags)
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
			c.Printf("getAuthz: error getting order URL: %v\n", err)
			return
		}
		targetURL, err = commands.FindAuthzURL(c, targetURL, opts.identifier)
	}

	if err != nil {
		c.Printf("getAuthz: error getting authz URL: %v\n", err)
		return
	}
	if targetURL == "" {
		c.Printf("getAuthz: target URL was empty\n")
		return
	}

	var authz = &resources.Authorization{
		ID: targetURL,
	}
	err = client.UpdateAuthz(authz)
	if err != nil {
		c.Printf("getAuthz: error getting authz: %s\n", err.Error())
		return
	}

	authzStr, err := commands.PrintJSON(authz)
	if err != nil {
		c.Printf("getAuthz: error serializing authz: %v\n", err)
		return
	}
	c.Printf("%s\n", authzStr)
}
