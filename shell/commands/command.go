// Package commands holds types and functions common across all ACMEShell
// commands.
package commands

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"strings"

	"github.com/abiosoft/ishell"
	acmeclient "github.com/cpu/acmeshell/acme/client"
	"github.com/cpu/acmeshell/acme/resources"
)

const (
	// The base prompt used for shell commands
	BasePrompt = "[ ACME ] > "
	// The ishell context key that we store a client instance under.
	ClientKey = "client"
	// The ishell context key that we store a challenge response server instance
	// under.
	ChallSrvKey = "challsrv"
)

func OkURL(urlStr string) bool {
	result, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	if result.Scheme != "http" && result.Scheme != "https" {
		return false
	}
	return true
}

// shellContext is a common interface that can be used to retrieve objects from
// a ishell.Shell or an ishell.Context.
type shellContext interface {
	Get(string) any
}

// GetClient reads a *acmeclient.Client from the shellContext or panics.
func GetClient(c shellContext) *acmeclient.Client {
	if c.Get(ClientKey) == nil {
		panic(fmt.Sprintf("nil %q value in shellContext", ClientKey))
	}

	rawClient := c.Get(ClientKey)
	switch c := rawClient.(type) {
	case *acmeclient.Client:
		return c
	}

	panic(fmt.Sprintf(
		"%q value in shellContext was not an *acmeclient.Client",
		ClientKey))
}

// GetChallSrv reads a challengeServer from the shellContext or panics.
func GetChallSrv(c shellContext) ChallengeServer {
	if c.Get(ChallSrvKey) == nil {
		panic(fmt.Sprintf("nil %q value in shellContext", ChallSrvKey))
	}

	rawSrv := c.Get(ChallSrvKey)
	switch c := rawSrv.(type) {
	case ChallengeServer:
		return c
	}

	panic(fmt.Sprintf(
		"%q value in shellContext was not a ChallengeServer",
		ChallSrvKey))
}

func ReadJSON(c *ishell.Context) string {
	c.SetPrompt(BasePrompt + "JSON > ")
	defer c.SetPrompt(BasePrompt)
	terminator := "."
	c.Printf("Input JSON POST request body. End by sending '%s'\n", terminator)
	return strings.TrimSuffix(c.ReadMultiLines(terminator), terminator)
}

func PrintJSON(ob any) (string, error) {
	bytes, err := json.MarshalIndent(ob, "", "  ")
	if err != nil {
		return "", err
	}
	return string(bytes), err
}

var commands []commandRegistry

type commandRegistry struct {
	Cmd           *ishell.Cmd
	Autocompleter NewCommandAutocompleter
}

type NewCommandAutocompleter func(c *acmeclient.Client) func(args []string) []string

func AddCommands(shell *ishell.Shell, client *acmeclient.Client) {
	for _, cmdReg := range commands {
		if cmdReg.Autocompleter != nil {
			cmdReg.Cmd.Completer = cmdReg.Autocompleter(client)
		}
		shell.AddCmd(cmdReg.Cmd)
	}
}

func RegisterCommand(
	cmd *ishell.Cmd,
	completerFunc NewCommandAutocompleter) {
	if cmd.Func == nil {
		panic(fmt.Sprintf(
			"Trying to RegisterCommand %q with nil handler Func\n",
			cmd.Name,
		))
	}
	commands = append(commands, commandRegistry{
		Cmd:           cmd,
		Autocompleter: completerFunc,
	})
}

// ParseFlagSetArgs parses the given args with the flagSet. If there is no error
// then (leftovers []string, nil) is returned where "leftovers" is the
// result of flagSet.Args() after parsing. If there is an err (including
// flag.ErrHelp) then (nil, err) is returned. Most callers will want to simply
// bail out of the command if there is an error because the flag package will
// have already printed the cause to stdout.
func ParseFlagSetArgs(args []string, flagSet *flag.FlagSet) ([]string, error) {
	if flagSet == nil {
		return nil, errors.New("flagSet argument was nil")
	}

	if err := flagSet.Parse(args); err != nil {
		return nil, err
	}

	return flagSet.Args(), nil
}

func DirectoryAutocompleter(c *acmeclient.Client) func(args []string) []string {
	dir, err := c.Directory()
	if err != nil {
		return nil
	}
	var keys []string
	for key := range dir {
		if key == "meta" {
			continue
		}
		keys = append(keys, key)
	}
	return func(args []string) []string {
		return keys
	}
}

func FindOrderURL(ctx *ishell.Context, leftovers []string, orderIndex int) (string, error) {
	var targetURL string
	var err error
	c := GetClient(ctx)
	// If there was no URL specified we need to find one based on the other args.
	if len(leftovers) == 0 {
		// If there was an order index, use it to lookup a order URL
		if orderIndex >= 0 {
			targetURL, err = c.ActiveAccount.OrderURL(orderIndex)
		} else {
			// Otherwise, pick an order interactively
			targetURL, err = PickOrderURL(ctx)
		}
	} else {
		// Otherwise treat the leftovers as a template or URL
		templateText := strings.Join(leftovers, " ")
		targetURL, err = ClientTemplate(c, templateText)
	}
	// If there was an error, return it and no URL
	if err != nil {
		return "", err
	}
	// If there's no URL (shouldn't happen!) then return an error
	if targetURL == "" {
		return "", errors.New("couldn't find a order URL with provided args")
	}
	return targetURL, nil
}

func FindAuthzURL(ctx *ishell.Context, orderURL string, identifier string) (string, error) {
	c := GetClient(ctx)
	order := &resources.Order{
		ID: orderURL,
	}
	err := c.UpdateOrder(order)
	if err != nil {
		return "", err
	}
	var authzURL string
	if identifier != "" {
		authz, err := c.AuthzByIdentifier(order, identifier)
		if err != nil {
			return "", err
		}
		authzURL = authz.ID
	} else {
		// Otherwise, pick an authz interactively
		authzURL, err = PickAuthzURL(ctx, order)
		if err != nil {
			return "", err
		}
	}
	return authzURL, nil
}

func FindChallengeURL(ctx *ishell.Context, authzURL string, challType string) (string, error) {
	c := GetClient(ctx)
	authz := &resources.Authorization{
		ID: authzURL,
	}
	if err := c.UpdateAuthz(authz); err != nil {
		return "", err
	}
	if challType != "" {
		for _, chall := range authz.Challenges {
			if chall.Type == challType {
				return chall.URL, nil
			}
		}
		return "", fmt.Errorf("authz %q has no %q type challenge", authzURL, challType)
	}
	chall, err := PickChall(ctx, authz)
	if err != nil {
		return "", err
	}
	return chall.URL, nil
}

func FindURL(c *acmeclient.Client, leftovers []string) (string, error) {
	if len(leftovers) == 0 {
		return "", fmt.Errorf("an argument is required")
	}
	argument := strings.TrimSpace(leftovers[0])
	// If the argument is "directory", use the directory URL as the target
	if argument == "directory" {
		return c.DirectoryURL.String(), nil
	}
	if endpointURL, ok := c.GetEndpointURL(argument); ok {
		// If the argument is an endpoint, find its URL
		return endpointURL, nil
	}
	templateText := strings.Join(leftovers, " ")
	return ClientTemplate(c, templateText)
}
