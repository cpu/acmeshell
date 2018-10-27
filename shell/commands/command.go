// Package commands holds types and functions common across all ACMEShell
// commands.
package commands

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"

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
	// The ishell context key that we store env settings under.
	EnvKey = "env"
)

// Environment holds runtime settings for an ACMEShell.
type Environment struct {
	// Print all HTTP requests made to the ACME server.
	PrintRequests bool
	// Print all HTTP responses from the ACME server.
	PrintResponses bool
	// Print all the input to JWS produced.
	PrintSignedData bool
	// Print the JSON serialization of all JWS produced.
	PrintJWS bool
}

// ACMEShellCmds can be Setup with a Client instance. This allows the command to
// setup auto-completers and other properties based on interactions with the
// client. Setup routines should return an ishell.Cmd instance.that an ACMEShell
// can register.
type ACMEShellCmd interface {
	Setup(client *acmeclient.Client) (*ishell.Cmd, error)
}

type BaseCmd struct {
	Once *sync.Once
	Cmd  *ishell.Cmd
}

func DirectoryKeyCompleter(
	directory map[string]interface{},
	extra []string) func([]string) []string {
	// Copy the directory map keys into an array of strings
	dirKeys := make([]string, len(directory))
	i := 0
	for key := range directory {
		dirKeys[i] = key
		i++
	}
	// Add the extra entries (if any)
	dirKeys = append(dirKeys, extra...)
	// Return a completer function for the directory keys + extras
	return func(args []string) []string {
		return dirKeys
	}
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

// GetEnviromment reads a *Environment from the shellContext or
// panics.
func GetEnvironment(c shellContext) *Environment {
	if c.Get(EnvKey) == nil {
		panic(fmt.Sprintf("nil %q value in shellContext", EnvKey))
	}

	rawEnv := c.Get(EnvKey)
	switch env := rawEnv.(type) {
	case *Environment:
		return env
	}

	panic(fmt.Sprintf(
		"%q value in shellContext was not an *Environment",
		EnvKey))
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
