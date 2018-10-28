package poll

import (
	"encoding/json"
	"flag"
	"time"

	"github.com/abiosoft/ishell"
	acmeclient "github.com/cpu/acmeshell/acme/client"
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
	// Reset the pollOptions to default after handling.
	defer func() {
		opts = pollOptions{
			orderIndex:   -1,
			maxTries:     5,
			sleepSeconds: 5,
			status:       "ready",
		}
	}()

	client := commands.GetClient(c)

	targetURL, err := commands.FindOrderURL(c, leftovers, opts.orderIndex)
	if err != nil {
		c.Printf("poll: error getting order URL: %v\n", err)
		return
	}

	if opts.identifier != "" {
		targetURL, err = commands.FindAuthzURL(c, targetURL, opts.identifier)
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

	pollURL(c, client, targetURL)
}

type polledOb struct {
	Status string
}

func pollObject(client *acmeclient.Client, targetURL string) (polledOb, error) {
	var ob polledOb
	resp, err := client.GetURL(targetURL)
	if err != nil {
		return ob, err
	}
	err = json.Unmarshal(resp.RespBody, &ob)
	if err != nil {
		return ob, err
	}
	return ob, nil
}

func pollURL(c *ishell.Context, client *acmeclient.Client, targetURL string) {
	ob, err := pollObject(client, targetURL)
	if err != nil {
		c.Printf("poll: error polling object at %q: %v\n", targetURL, err)
		return
	}

	if ob.Status != opts.status {
		for try := 0; try < opts.maxTries; try++ {
			ob, err := pollObject(client, targetURL)
			if err != nil {
				c.Printf("poll: error polling object at %q: %v\n", targetURL, err)
				return
			}
			if ob.Status == opts.status {
				break
			}

			c.Printf("poll: try %d. %q is status %q\n", try, targetURL, ob.Status)
			time.Sleep(time.Duration(opts.sleepSeconds) * time.Second)
		}
	}

	if ob.Status == opts.status {
		c.Printf("poll: polling done. %q is status %q\n",
			targetURL,
			ob.Status)
	} else {
		c.Printf("poll: polling failed. reached %d tries. %q is status %q\n",
			opts.maxTries,
			targetURL,
			ob.Status)
	}
}
