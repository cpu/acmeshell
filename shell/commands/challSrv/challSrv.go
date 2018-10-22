package challSrv

import (
	"flag"

	"github.com/abiosoft/ishell"
	acmeclient "github.com/cpu/acmeshell/acme/client"
	"github.com/cpu/acmeshell/shell/commands"
)

type challSrvCmd struct {
	commands.BaseCmd
}

type challSrvOptions struct {
	challengeType string
	token         string
	host          string
	value         string
	operation     string
}

var ChallSrvCommand challSrvCmd = challSrvCmd{
	commands.BaseCmd{
		Cmd: &ishell.Cmd{
			Name:     "challSrv",
			Aliases:  []string{"chalSrv", "challengeServer"},
			Func:     challSrvHandler,
			Help:     "Add/remove challenge responses from the embedded challenge response server",
			LongHelp: `TODO(@cpu): Write this!`,
		},
	},
}

func (c challSrvCmd) Setup(client *acmeclient.Client) (*ishell.Cmd, error) {
	return ChallSrvCommand.Cmd, nil
}

func challSrvHandler(c *ishell.Context) {
	opts := challSrvOptions{}
	challSrvFlags := flag.NewFlagSet("challSrv", flag.ContinueOnError)
	challSrvFlags.StringVar(&opts.challengeType, "challengeType", "", "Challenge type to add/remove")
	challSrvFlags.StringVar(&opts.token, "token", "", "Challenge token (HTTP-01 only)")
	challSrvFlags.StringVar(&opts.host, "host", "", "Challenge response host (DNS-01/TLS-ALPN-01 only)")
	challSrvFlags.StringVar(&opts.value, "value", "", "Challenge response value")
	challSrvFlags.StringVar(&opts.operation, "operation", "add", "'add' to add a challenge, 'del' to remove")

	err := challSrvFlags.Parse(c.Args)
	if err != nil && err != flag.ErrHelp {
		c.Printf("challSrv: error parsing input flags: %s\n", err.Error())
		return
	} else if err == flag.ErrHelp {
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
		"http-01": challengeType{
			adder:   challSrv.AddHTTPOneChallenge,
			remover: challSrv.DeleteHTTPOneChallenge,
		},
		"dns-01": challengeType{
			adder:   challSrv.AddDNSOneChallenge,
			remover: challSrv.DeleteDNSOneChallenge,
		},
		"tls-alpn-01": challengeType{
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
