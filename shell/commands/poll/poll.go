package poll

import (
	"encoding/json"
	"flag"
	"time"

	"github.com/abiosoft/ishell"
	acmeclient "github.com/cpu/acmeshell/acme/client"
	"github.com/cpu/acmeshell/net"
	"github.com/cpu/acmeshell/shell/commands"
)

type pollOptions struct {
	maxTries     int
	sleepSeconds int
	status       string
	orderIndex   int
	identifier   string
}

func init() {
	registerPollCommand()
}

func registerPollCommand() {
	commands.RegisterCommand(
		&ishell.Cmd{
			Name:     "poll",
			Help:     "Poll an order or authz until it is has the desired status field value",
			LongHelp: `TODO(@cpu): Write the poll cmd longHelp`,
		},
		nil,
		pollHandler,
		nil)
}

func pollHandler(c *ishell.Context, args []string) {
	newOpts := pollOptions{}
	newFlags := flag.NewFlagSet("poll", flag.ContinueOnError)
	newFlags.StringVar(&newOpts.status, "status", "ready", "Poll object until it is the given status")
	newFlags.IntVar(&newOpts.maxTries, "maxTries", 5, "Number of times to poll before giving up")
	newFlags.IntVar(&newOpts.sleepSeconds, "sleep", 5, "Number of seconds to sleep between poll attempts")
	newFlags.IntVar(&newOpts.orderIndex, "order", -1, "index of order to poll")
	newFlags.StringVar(&newOpts.identifier, "identifier", "", "identifier of authorization")

	err := newFlags.Parse(args)

	// If it was an error and not the -h error, print a message and return early.
	if err != nil && err != flag.ErrHelp {
		c.Printf("poll: error parsing input flags: %v\n", err)
		return
	} else if err == flag.ErrHelp {
		// If it was the -h err, just return early. The help was already printed.
		return
	}
	leftovers := newFlags.Args()

	client := commands.GetClient(c)

	targetURL, err := commands.FindOrderURL(c, leftovers, newOpts.orderIndex)
	if err != nil {
		c.Printf("poll: error getting order URL: %v\n", err)
		return
	}

	if newOpts.identifier != "" {
		targetURL, err = commands.FindAuthzURL(c, targetURL, newOpts.identifier)
		if err != nil {
			c.Printf("poll: error getting order URL: %v\n", err)
			return
		}
	}

	// Shouldn't happen...
	if targetURL == "" {
		c.Printf("poll: error, no targetURL\n")
		return
	}

	pollURL(c, client, targetURL, newOpts)
}

type polledOb struct {
	Status string
}

func pollObject(client *acmeclient.Client, targetURL string, newOpts pollOptions) (polledOb, error) {
	var ob polledOb
	var resp *net.NetResponse
	var err error
	if client.PostAsGet {
		resp, err = client.PostAsGetURL(targetURL)
	} else {
		resp, err = client.GetURL(targetURL)
	}
	if err != nil {
		return ob, err
	}

	err = json.Unmarshal(resp.RespBody, &ob)
	if err != nil {
		return ob, err
	}
	return ob, nil
}

func pollURL(c *ishell.Context, client *acmeclient.Client, targetURL string, newOpts pollOptions) {
	ob, err := pollObject(client, targetURL, newOpts)
	if err != nil {
		c.Printf("poll: error polling object at %q: %v\n", targetURL, err)
		return
	}

	if ob.Status != newOpts.status {
		for try := 0; try < newOpts.maxTries; try++ {
			ob, err = pollObject(client, targetURL, newOpts)
			if err != nil {
				c.Printf("poll: error polling object at %q: %v\n", targetURL, err)
				return
			}
			if ob.Status == newOpts.status {
				break
			}

			c.Printf("poll: try %d. %q is status %q\n", try, targetURL, ob.Status)
			time.Sleep(time.Duration(newOpts.sleepSeconds) * time.Second)
		}
	}

	if ob.Status == newOpts.status {
		c.Printf("poll: polling done. %q is status %q\n",
			targetURL,
			ob.Status)
	} else {
		c.Printf("poll: polling failed. reached %d tries. %q is status %q\n",
			newOpts.maxTries,
			targetURL,
			ob.Status)
	}
}
