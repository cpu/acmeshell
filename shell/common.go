package shell

import (
	"fmt"
	"net/url"

	"github.com/abiosoft/ishell"
	"github.com/cpu/acmeshell/acme"
	"github.com/letsencrypt/boulder/test/challtestsrv"
)

const (
	ClientKey   = "client"
	ChallSrvKey = "challsrv"
	BasePrompt  = "[ ACME ] > "
)

type AcmeCmd interface {
	New(client *acme.Client) *ishell.Cmd
}

var Commands []AcmeCmd = []AcmeCmd{
	get,
	// TODO: Make all of this junk unexported
	Post,
	Accounts,
	NewAccount,
	LoadAccount,
	SwitchAccount,
	NewOrder,
	Orders,
	sign,
	CSR,
	viewKey,
	newKey,
	loadKey,
	keyRollover,
	poll,
	solve,
	finalize,
	getOrder,
	getAuthz,
	getChall,
	getCert,
	getAccount,
	echo,
	challSrv,
}

func getClient(c *ishell.Context) *acme.Client {
	if c.Get(ClientKey) == nil {
		panic(fmt.Sprintf("nil %q value in ishell.Context", ClientKey))
	}

	rawClient := c.Get(ClientKey)
	switch c := rawClient.(type) {
	case *acme.Client:
		return c
	}

	panic(fmt.Sprintf("%q value in ishell.Context was not an *acme.Client", ClientKey))
}

func getChallSrv(c *ishell.Context) *challtestsrv.ChallSrv {
	if c.Get(ChallSrvKey) == nil {
		panic(fmt.Sprintf("nil %q value in ishell.Context", ChallSrvKey))
	}

	rawSrv := c.Get(ChallSrvKey)
	switch c := rawSrv.(type) {
	case *challtestsrv.ChallSrv:
		return c
	}

	panic(fmt.Sprintf("%q value in ishell.Context was not a *challtestsrv.ChallSrv", ChallSrvKey))
}

func okURL(urlStr string) bool {
	result, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	if result.Scheme != "http" && result.Scheme != "https" {
		return false
	}
	return true
}

func directoryKeyCompleter(
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
