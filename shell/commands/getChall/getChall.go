package getChall

import (
	"flag"
	"strings"

	"github.com/abiosoft/ishell"
	"github.com/cpu/acmeshell/acme/resources"
	"github.com/cpu/acmeshell/shell/commands"
)

type getChallOptions struct {
	orderIndex int
	identifier string
	challType  string
}

var (
	opts = getChallOptions{}
)

func init() {
	registerGetChallCmd()
}

func registerGetChallCmd() {
	getChallFlags := flag.NewFlagSet("getChall", flag.ContinueOnError)
	getChallFlags.IntVar(&opts.orderIndex, "order", -1, "index of existing order")
	getChallFlags.StringVar(&opts.identifier, "identifier", "", "identifier of authorization")
	getChallFlags.StringVar(&opts.challType, "type", "", "challenge type to get")

	commands.RegisterCommand(
		&ishell.Cmd{
			Name:     "getChall",
			Aliases:  []string{"challenge", "chall"},
			Help:     "Get an ACME challenge URL",
			LongHelp: `TODO(@cpu): Write this!`,
		},
		nil,
		getChallHandler,
		getChallFlags)
}

func getChallHandler(c *ishell.Context, leftovers []string) {
	defer func() {
		opts = getChallOptions{
			orderIndex: -1,
		}
	}()

	client := commands.GetClient(c)

	var targetURL string
	var err error
	if len(leftovers) > 0 {
		templateText := strings.Join(leftovers, " ")
		targetURL, err = commands.ClientTemplate(client, templateText)
		if err != nil {
			c.Printf("getChall: error templating order URL: %v\n", err)
			return
		}
	} else {
		targetURL, err = commands.FindOrderURL(c, nil, opts.orderIndex)
		if err != nil {
			c.Printf("getChall: error getting order URL: %v\n", err)
			return
		}
		targetURL, err = commands.FindAuthzURL(c, targetURL, opts.identifier)
		if err != nil {
			c.Printf("getChall: error getting authz URL: %v\n", err)
			return
		}
		targetURL, err = commands.FindChallengeURL(c, targetURL, opts.challType)
		if err != nil {
			c.Printf("getChall: error getting challenge URL: %v\n", err)
			return
		}
	}

	chall := &resources.Challenge{
		URL: targetURL,
	}
	err = client.UpdateChallenge(chall)
	if err != nil {
		c.Printf("getChall: error getting authz: %s\n", err.Error())
		return
	}
	challStr, err := commands.PrintJSON(chall)
	if err != nil {
		c.Printf("getChall: error serializing challenge: %v\n", err)
		return
	}
	c.Printf("%s\n", challStr)
}
