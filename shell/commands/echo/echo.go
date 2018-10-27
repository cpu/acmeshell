package echo

import (
	"strings"

	"github.com/abiosoft/ishell"
	acmeclient "github.com/cpu/acmeshell/acme/client"
	"github.com/cpu/acmeshell/shell/commands"
)

type echoCmd struct {
	commands.BaseCmd
}

var EchoCommand = echoCmd{
	commands.BaseCmd{
		Cmd: &ishell.Cmd{
			Name:     "echo",
			Func:     echoHandler,
			Help:     "Output a message",
			LongHelp: "Useful for non-interactive scripts (must escape all special characters)",
		},
	},
}

func (e echoCmd) Setup(client *acmeclient.Client) (*ishell.Cmd, error) {
	return EchoCommand.Cmd, nil
}

func echoHandler(c *ishell.Context) {
	c.Printf("# %s\n", strings.Join(c.Args, " "))
}
