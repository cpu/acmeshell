package client

import (
	"net/http"
	"net/http/httputil"
)

type HTTPOptions struct {
	PrintResponse bool
	PrintRequest  bool
}

// TODO(@cpu): update this
type HTTPPostOptions struct {
	HTTPOptions
	PrintJWS       bool
	PrintJWSObject bool
	PrintJSON      bool
}

type ResponseCtx struct {
	Body []byte
	Resp *http.Response
	Err  error
}

var (
	defaultHTTPOptions = &HTTPOptions{
		PrintRequest:  false,
		PrintResponse: false,
	}
	defaultHTTPPostOptions = &HTTPPostOptions{
		HTTPOptions:    *defaultHTTPOptions,
		PrintJWS:       false,
		PrintJWSObject: false,
		PrintJSON:      false,
	}
)

func (c *Client) handleRequest(req *http.Request, opts *HTTPOptions) ResponseCtx {
	if opts == nil {
		opts = defaultHTTPOptions
	}
	if opts.PrintRequest {
		httputil.DumpRequest(req, true)
	}
	respBody, resp, err := c.net.Do(req)
	if opts.PrintResponse {
		httputil.DumpResponse(resp, true)
	}
	return ResponseCtx{
		Body: respBody,
		Resp: resp,
		Err:  err,
	}
}

func (c *Client) GetURL(url string, opts *HTTPOptions) ResponseCtx {
	req, err := c.net.GetRequest(url)
	if err != nil {
		return ResponseCtx{
			Err: err,
		}
	}
	return c.handleRequest(req, opts)
}

// NOTE(@cpu): PostURL takes *HTTPOptions not HTTPPostOptions because its badly
// named. HTTPPostOptions is a higher level JWS type thing.
func (c *Client) PostURL(url string, body []byte, opts *HTTPOptions) ResponseCtx {
	req, err := c.net.PostRequest(url, body)
	if err != nil {
		return ResponseCtx{
			Err: err,
		}
	}
	return c.handleRequest(req, opts)
}
