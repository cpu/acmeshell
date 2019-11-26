// Package net provides common HTTP utilities.
package net

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"runtime"
)

const (
	version       = "0.0.1"
	userAgentBase = "cpu.acmeshell"
	locale        = "en-us"
)

type ACMENet struct {
	httpClient *http.Client
}

func New(customCABundle string) (*ACMENet, error) {
	var caBundle *x509.CertPool
	if customCABundle != "" {
		pemBundle, err := ioutil.ReadFile(customCABundle)
		if err != nil {
			return nil, err
		}

		caBundle = x509.NewCertPool()
		caBundle.AppendCertsFromPEM(pemBundle)
	}

	return &ACMENet{
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: caBundle,
				},
			},
		},
	}, nil
}

// NetResponse holds the results from calling Do with an HTTP Request.
type NetResponse struct {
	// The HTTP Response object from making the request.
	Response *http.Response
	// The response body.
	RespBody []byte
	// The response dumped by httputil to a printable form.
	RespDump []byte
	// The request dumped by httputil to a printable form.
	ReqDump []byte
}

// Do performs an HTTP request, returning a pointer to a NetResponse instance or
// an error. User-Agent and Accept-Language headers are automatically added. to
// the request. The body of the HTTP Response is read into the NetResponse and
// can not be read again.
func (c *ACMENet) Do(req *http.Request) (*NetResponse, error) {
	return c.httpRequest(req)
}

func (c *ACMENet) httpRequest(req *http.Request) (*NetResponse, error) {
	ua := fmt.Sprintf("%s %s (%s; %s)",
		userAgentBase, version, runtime.GOOS, runtime.GOARCH)
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept-Language", locale)

	reqDump, err := httputil.DumpRequest(req, true)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respDump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		return nil, err
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return &NetResponse{
		Response: resp,
		RespBody: respBody,
		RespDump: respDump,
		ReqDump:  reqDump,
	}, nil
}

func (c *ACMENet) HeadURL(url string) (*http.Response, error) {
	return c.httpClient.Head(url)
}

// Convenience function to construct a POST request to the given URL with the
// given body. Returns an HTTP request or a non-nil error.
func (c *ACMENet) PostRequest(url string, body []byte) (*http.Request, error) {
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/jose+json")
	return req, nil
}

// Convenience function to POST the given URL with the given body. This is
// a wrapper combining PostRequest and Do.
func (c *ACMENet) PostURL(url string, body []byte) (*NetResponse, error) {
	req, err := c.PostRequest(url, body)
	if err != nil {
		return nil, err
	}

	return c.Do(req)
}

// Convenience function to construct a GET request to the given URL. Returns an
// HTTP request or a non-nil error.
func (c *ACMENet) GetRequest(url string) (*http.Request, error) {
	return http.NewRequest("GET", url, nil)
}

// Convenience function to GET the given URL. This is a wrapper combining
// GetRequest and Do.
func (c *ACMENet) GetURL(url string) (*NetResponse, error) {
	req, err := c.GetRequest(url)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}
