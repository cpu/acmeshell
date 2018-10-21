package shell

import (
	"strings"

	"github.com/abiosoft/ishell"
	acmeclient "github.com/cpu/acmeshell/acme/client"
)

type echoCmd struct {
	cmd *ishell.Cmd
}

var echo echoCmd = echoCmd{
	cmd: &ishell.Cmd{
		Name:     "echo",
		Func:     echoHandler,
		Help:     "Output a message",
		LongHelp: "Useful for non-interactive scripts (must escape all special characters)",
	},
}

func (e echoCmd) New(client *acmeclient.Client) *ishell.Cmd {
	return echo.cmd
}

func echoHandler(c *ishell.Context) {
	c.Printf("# %s\n", strings.Join(c.Args, " "))
}
