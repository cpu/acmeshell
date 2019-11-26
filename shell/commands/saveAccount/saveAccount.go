package saveAccount

import (
	"flag"

	"github.com/abiosoft/ishell"
	"github.com/cpu/acmeshell/acme/resources"
	"github.com/cpu/acmeshell/shell/commands"
)

func init() {
	commands.RegisterCommand(
		&ishell.Cmd{
			Name:     "saveAccount",
			Aliases:  []string{"save", "saveReg", "saveRegistration"},
			Help:     "Save the active ACME account",
			LongHelp: `TODO(@cpu): Write this!`,
			Func:     saveAccountHandler,
		},
		nil)
}

type saveAccountOptions struct {
	jsonPath string
}

func saveAccountHandler(c *ishell.Context) {
	opts := saveAccountOptions{}
	saveAccountFlags := flag.NewFlagSet("saveAccount", flag.ContinueOnError)
	saveAccountFlags.StringVar(&opts.jsonPath, "json", "", "Filepath to a JSON save file for the account. If empty the -account argument is used")

	if _, err := commands.ParseFlagSetArgs(c.Args, saveAccountFlags); err != nil {
		return
	}

	client := commands.GetClient(c)

	acct := client.ActiveAccount
	if acct == nil {
		c.Printf("no active account to save")
		return
	}

	jsonPath := acct.Path()
	if opts.jsonPath != "" {
		jsonPath = opts.jsonPath
	}

	if jsonPath == "" {
		c.Printf("no -json path provided and active account has no default path.")
		return
	}

	if err := resources.SaveAccount(jsonPath, acct); err != nil {
		c.Printf("error saving account to %q : %v\n", jsonPath, err)
		return
	}

	c.Printf("Saved active account data to %q\n", jsonPath)
}
