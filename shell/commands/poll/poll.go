package poll

import (
	"encoding/json"
	"flag"
	"strings"
	"time"

	"github.com/abiosoft/ishell"
	"github.com/cpu/acmeshell/acme/resources"
	"github.com/cpu/acmeshell/shell/commands"
)

type pollOptions struct {
	maxTries     int
	sleepSeconds int
	status       string
	orderIndex   int
	identifier   string
}

var (
	opts = pollOptions{}
)

func init() {
	registerPollCommand()
}

func registerPollCommand() {
	pollFlags := flag.NewFlagSet("poll", flag.ContinueOnError)
	pollFlags.StringVar(&opts.status, "status", "ready", "Poll object until it is the given status")
	pollFlags.IntVar(&opts.maxTries, "maxTries", 5, "Number of times to poll before giving up")
	pollFlags.IntVar(&opts.sleepSeconds, "sleep", 5, "Number of seconds to sleep between poll attempts")
	pollFlags.IntVar(&opts.orderIndex, "order", -1, "index of order to poll")
	pollFlags.StringVar(&opts.identifier, "identifier", "", "identifier of authorization")

	commands.RegisterCommand(
		&ishell.Cmd{
			Name:     "poll",
			Help:     "Poll an order or authz until it is has the desired status field value",
			LongHelp: `TODO(@cpu): Write the poll cmd longHelp`,
		},
		nil,
		pollHandler,
		pollFlags)
}

func pollHandler(c *ishell.Context, leftovers []string) {
	client := commands.GetClient(c)

	var targetURL string
	if len(leftovers) == 0 {
		if len(client.ActiveAccount.Orders) == 0 {
			c.Printf("poll: the active account has no orders\n")
			return
		}
		order := &resources.Order{}
		var err error
		if opts.orderIndex >= 0 && opts.orderIndex < len(client.ActiveAccount.Orders) {
			orderURL := client.ActiveAccount.Orders[opts.orderIndex]
			order.ID = orderURL
			err := client.UpdateOrder(order)
			if err != nil {
				c.Printf("poll: error getting order: %s\n", err.Error())
				return
			}
		} else {
			order, err = commands.PickOrder(c)
			if err != nil {
				c.Printf("poll: error picking order: %s\n", err.Error())
				return
			}
		}
		if opts.identifier == "" {
			targetURL = order.ID
		} else {
			for _, authzURL := range order.Authorizations {
				authz := &resources.Authorization{
					ID: authzURL,
				}
				err := client.UpdateAuthz(authz)
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
		targetURL = strings.Join(leftovers, " ")
	}

	var polledOb struct {
		Status string
	}

	resp, err := client.GetURL(targetURL)
	if err != nil {
		c.Printf("poll: error polling %q : %v\n", targetURL, err)
		return
	}

	err = json.Unmarshal(resp.RespBody, &polledOb)
	if err != nil {
		c.Printf("poll: error unmarshaling %q : %s\n", targetURL, err.Error())
		return
	}

	if polledOb.Status != opts.status {
		for try := 0; try < opts.maxTries; try++ {

			resp, err := client.GetURL(targetURL)
			if err != nil {
				c.Printf("poll: error polling %q : %v\n", targetURL, err)
				return
			}

			err = json.Unmarshal(resp.RespBody, &polledOb)
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
