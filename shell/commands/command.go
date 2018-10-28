// Package commands holds types and functions common across all ACMEShell
// commands.
package commands

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"strings"

	"github.com/abiosoft/ishell"
	acmeclient "github.com/cpu/acmeshell/acme/client"
	"github.com/cpu/acmeshell/challtestsrv"
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

// ACMEShellCmds can be Setup with a Client instance. This allows the command to
// setup auto-completers and other properties based on interactions with the
// client. Setup routines should return an ishell.Cmd instance.that an ACMEShell
// can register.
//
// TODO(@cpu): Remove this crap
type ACMEShellCmd interface {
	Setup(client *acmeclient.Client) (*ishell.Cmd, error)
}

// TODO(@cpu): Remove this crap
type BaseCmd struct {
	Cmd *ishell.Cmd
}

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
	Get(string) interface{}
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

// GetChallSrv reads a *challtestsrv.ChallSrv from the shellContext or panics.
func GetChallSrv(c shellContext) *challtestsrv.ChallSrv {
	if c.Get(ChallSrvKey) == nil {
		panic(fmt.Sprintf("nil %q value in shellContext", ChallSrvKey))
	}

	rawSrv := c.Get(ChallSrvKey)
	switch c := rawSrv.(type) {
	case *challtestsrv.ChallSrv:
		return c
	}

	panic(fmt.Sprintf(
		"%q value in shellContext was not a *challtestsrv.ChallSrv",
		ChallSrvKey))
}

func ReadJSON(c *ishell.Context) string {
	c.SetPrompt(BasePrompt + "JSON > ")
	defer c.SetPrompt(BasePrompt)
	terminator := "."
	c.Printf("Input JSON POST request body. End by sending '%s'\n", terminator)
	return strings.TrimSuffix(c.ReadMultiLines(terminator), terminator)
}

func PrintJSON(ob interface{}) (string, error) {
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

type NewCommandHandler func(c *ishell.Context, leftovers []string)

func RegisterCommand(
	cmd *ishell.Cmd,
	completerFunc NewCommandAutocompleter,
	handler NewCommandHandler,
	flags *flag.FlagSet) {
	if flags == nil {
		flags = flag.NewFlagSet(cmd.Name, flag.ContinueOnError)
	}
	// Stomp the cmd's Func with a wrapped version that will call the
	// NewCommandHandler to parse the flags.
	cmd.Func = wrapHandler(cmd.Name, handler, flags)
	commands = append(commands, commandRegistry{
		Cmd:           cmd,
		Autocompleter: completerFunc,
	})
}

func wrapHandler(name string, handler NewCommandHandler, flags *flag.FlagSet) func(*ishell.Context) {
	return func(c *ishell.Context) {
		// Parse the command's flags with the context args.
		err := flags.Parse(c.Args)
		// If it was an error adn not the -h error, print a message and return early.
		if err != nil && err != flag.ErrHelp {
			c.Printf("%s: error parsing input flags: %v\n", name, err)
			return
		} else if err == flag.ErrHelp {
			// If it was the -h err, just return early. The help was already printed.
			return
		}

		// Call the wrapped NewCommandHandler with the leftover args from flag
		// parsing.
		handler(c, flags.Args())
	}
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
