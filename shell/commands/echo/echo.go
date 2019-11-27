package echo

import (
	"strings"

	"github.com/abiosoft/ishell"
	"github.com/cpu/acmeshell/shell/commands"
)

func init() {
	commands.RegisterCommand(
		&ishell.Cmd{
			Name:     "echo",
			Help:     "Output a message",
			LongHelp: "Useful for non-interactive scripts (must escape all special characters)",
			Func:     echoHandler,
		},
		nil)
}

func echoHandler(c *ishell.Context) {
	c.Printf("# %s\n", strings.Join(c.Args, " "))
}
