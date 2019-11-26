package challSrv

import (
	"flag"

	"github.com/abiosoft/ishell"
	"github.com/cpu/acmeshell/shell/commands"
)

const (
	longHelp = `TODO(@cpu): write challSrv LongHelp`
)

func init() {
	commands.RegisterCommand(
		&ishell.Cmd{
			Name:     "challSrv",
			Aliases:  []string{"chalSrv", "challengeServer"},
			Help:     "Add/remove challenge responses from the embedded challenge response server",
			LongHelp: longHelp,
		},
		nil,
		challSrvHandler,
		nil)
}

type challSrvOptions struct {
	challengeType string
	token         string
	host          string
	value         string
	operation     string
}

func challSrvHandler(c *ishell.Context, args []string) {
	var opts challSrvOptions
	challSrvFlags := flag.NewFlagSet("challSrv", flag.ContinueOnError)
	challSrvFlags.StringVar(&opts.challengeType, "challengeType", "", "Challenge type to add/remove")
	challSrvFlags.StringVar(&opts.token, "token", "", "Challenge token (HTTP-01 only)")
	challSrvFlags.StringVar(&opts.host, "host", "", "Challenge response host (DNS-01/TLS-ALPN-01 only)")
	challSrvFlags.StringVar(&opts.value, "value", "", "Challenge response value")
	challSrvFlags.StringVar(&opts.operation, "operation", "add", "'add' to add a challenge, 'del' to remove")

	if _, err := commands.ParseFlagSetArgs(args, challSrvFlags); err != nil {
		return
	}

	if opts.operation != "add" && opts.operation != "delete" {
		c.Printf("challSrv: -operation must be \"add\" or \"delete\"\n")
		return
	}
	if opts.challengeType == "http-01" && opts.host != "" {
		c.Printf("challSrv: -challengeType http-01 does not use a -host argument\n")
		return
	}
	if opts.challengeType != "http-01" && opts.token != "" {
		c.Printf("challSrv: only -challengeType http-01 uses a -token argument\n")
		return
	}
	if opts.challengeType != "http-01" && opts.challengeType != "dns-01" && opts.challengeType != "tls-alpn-01" {
		c.Printf("challSrv: -challengeType must be one of http-01, dns-01 or tls-alpn-01\n")
		return
	}

	challSrv := commands.GetChallSrv(c)

	type challengeAdder func(string, string)
	type challengeRemover func(string)

	type challengeType struct {
		adder   challengeAdder
		remover challengeRemover
	}

	challengeHandlers := map[string]challengeType{
		"http-01": {
			adder:   challSrv.AddHTTPOneChallenge,
			remover: challSrv.DeleteHTTPOneChallenge,
		},
		"dns-01": {
			adder:   challSrv.AddDNSOneChallenge,
			remover: challSrv.DeleteDNSOneChallenge,
		},
		"tls-alpn-01": {
			adder:   challSrv.AddTLSALPNChallenge,
			remover: challSrv.DeleteTLSALPNChallenge,
		},
	}

	operation := opts.operation
	challType := opts.challengeType

	host := opts.host
	if challType == "http-01" {
		host = opts.token
	}
	value := opts.value

	if operation == "add" {
		c.Printf("Adding %s challenge response for host %q\n", challType, host)
		challengeHandlers[challType].adder(host, value)
	} else {
		c.Printf("Removing %s challenge response for host %q\n", challType, host)
		challengeHandlers[challType].remover(host)
	}
}
