package echo

import (
	"strings"

	"github.com/abiosoft/ishell"
	"github.com/cpu/acmeshell/shell/commands"
)

func init() {
	registerEchoCmd()
}

func registerEchoCmd() {
	commands.RegisterCommand(
		&ishell.Cmd{
			Name:     "echo",
			Help:     "Output a message",
			LongHelp: "Useful for non-interactive scripts (must escape all special characters)",
		},
		nil,
		echoHandler,
		nil)
}

func echoHandler(c *ishell.Context, leftovers []string) {
	c.Printf("# %s\n", strings.Join(leftovers, " "))
}
