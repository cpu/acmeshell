package shell

import (
	"encoding/json"
	"flag"
	"strings"
	"time"

	"github.com/abiosoft/ishell"
	"github.com/cpu/acmeshell/acme"
)

type pollCmd struct {
	cmd *ishell.Cmd
}

type pollOptions struct {
	maxTries     int
	sleepSeconds int
	status       string
	orderIndex   int
	identifier   string
}

var poll pollCmd = pollCmd{
	cmd: &ishell.Cmd{
		Name:     "poll",
		Func:     pollHandler,
		Help:     "Poll an object until it is in the desired status",
		LongHelp: `TODO(@cpu): write this`,
	},
}

func (a pollCmd) New(client *acme.Client) *ishell.Cmd {
	return poll.cmd
}

func pollHandler(c *ishell.Context) {
	opts := pollOptions{}
	pollFlags := flag.NewFlagSet("poll", flag.ContinueOnError)
	pollFlags.StringVar(&opts.status, "status", "ready", "Poll object until it is the given status")
	pollFlags.IntVar(&opts.maxTries, "maxTries", 5, "Number of times to poll before giving up")
	pollFlags.IntVar(&opts.sleepSeconds, "sleep", 5, "Number of seconds to sleep between poll attempts")
	pollFlags.IntVar(&opts.orderIndex, "order", -1, "index of order to poll")
	pollFlags.StringVar(&opts.identifier, "identifier", "", "identifier of authorization")

	err := pollFlags.Parse(c.Args)
	if err != nil && err != flag.ErrHelp {
		c.Printf("poll: error parsing input flags: %s\n", err.Error())
		return
	} else if err == flag.ErrHelp {
		return
	}

	client := getClient(c)

	var targetURL string
	if len(pollFlags.Args()) == 0 {
		if len(client.ActiveAccount.Orders) == 0 {
			c.Printf("poll: the active account has no orders\n")
			return
		}
		var order *acme.Order
		if opts.orderIndex >= 0 && opts.orderIndex < len(client.ActiveAccount.Orders) {
			orderURL := client.ActiveAccount.Orders[opts.orderIndex]
			order, err = getOrderObject(client, orderURL, nil)
			if err != nil {
				c.Printf("poll: error getting order: %s\n", err.Error())
				return
			}
		} else {
			order, err = pickOrder(c)
			if err != nil {
				c.Printf("poll: error picking order: %s\n", err.Error())
				return
			}
		}
		if opts.identifier == "" {
			targetURL = order.ID
		} else {
			for _, authzURL := range order.Authorizations {
				authz, err := getAuthzObject(client, authzURL, nil)
				if err != nil {
					c.Printf("poll: error getting authz %q : %s\n", authzURL, err.Error())
					return
				}
				if authz.Identifier.Value == opts.identifier {
					targetURL = authz.ID
					break
				}
			}
			if targetURL == "" {
				c.Printf("poll: order %q had no authz for identifier %q\n", order.ID, opts.identifier)
				return
			}
		}
	} else {
		targetURL = strings.Join(pollFlags.Args(), " ")
	}

	var polledOb struct {
		Status string
	}

	respCtx := client.GetURL(targetURL, nil)
	if respCtx.Err != nil {
		c.Printf("poll: error polling %q : %s\n", targetURL, respCtx.Err.Error())
		return
	}

	err = json.Unmarshal(respCtx.Body, &polledOb)
	if err != nil {
		c.Printf("poll: error unmarshaling %q : %s\n", targetURL, err.Error())
		return
	}

	if polledOb.Status != opts.status {
		for try := 0; try < opts.maxTries; try++ {

			respCtx := client.GetURL(targetURL, nil)
			if respCtx.Err != nil {
				c.Printf("poll: error polling %q : %s\n", targetURL, err.Error())
				return
			}

			err := json.Unmarshal(respCtx.Body, &polledOb)
			if err != nil {
				c.Printf("poll: error unmarshaling %q : %s\n", targetURL, err.Error())
				return
			}
			if polledOb.Status == opts.status {
				break
			}

			c.Printf("poll: try %d. %q is status %q\n", try, targetURL, polledOb.Status)
			time.Sleep(time.Duration(opts.sleepSeconds) * time.Second)
		}
	}

	if polledOb.Status == opts.status {
		c.Printf("poll: polling done. %q is status %q\n", targetURL, polledOb.Status)
	} else {
		c.Printf("poll: polling failed. reached %d tries. %q is status %q\n", opts.maxTries, targetURL, polledOb.Status)
	}
}
