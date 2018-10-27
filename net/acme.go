// Package net provides common HTTP utilities.
package net

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"runtime"
	"strings"
)

const (
	version       = "0.0.1"
	userAgentBase = "cpu.acmeshell"
	locale        = "en-us"
)

type Config struct {
	CABundlePath string
}

func (c *Config) normalize() error {
	// Strip spaces from both config fields
	c.CABundlePath = strings.TrimSpace(c.CABundlePath)

	if c.CABundlePath == "" {
		return fmt.Errorf("CABundlePath must not be empty")
	}

	// It's good!
	return nil
}

type ACMENet struct {
	httpClient *http.Client
}

func New(conf Config) (*ACMENet, error) {
	if err := conf.normalize(); err != nil {
		return nil, err
	}

	pemBundle, err := ioutil.ReadFile(conf.CABundlePath)
	if err != nil {
		return nil, err
	}

	caBundle := x509.NewCertPool()
	caBundle.AppendCertsFromPEM(pemBundle)

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

type NetResponse struct {
	Response *http.Response
	RespBody []byte
	RespDump []byte
	ReqDump  []byte
}

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
	log.Printf("Sending HEAD request to URL %q\n", url)
	return c.httpClient.Head(url)
}

// Convenience function to construct a POST request to the given URL with the
// given body. Returns an HTTP request or a non-nil error.
func (c *ACMENet) PostRequest(url string, body []byte) (*http.Request, error) {
	return http.NewRequest("POST", url, bytes.NewBuffer(body))
}

// Convenience function to POST the given URL with the given body. This is
// a wrapper combining PostRequest and Do.
func (c *ACMENet) PostURL(url string, body []byte) (*NetResponse, error) {
	log.Printf("Sending POST request to URL %q\n", url)
	req, err := c.PostRequest(url, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/jose+json")
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
	log.Printf("Sending GET request to URL %q\n", url)
	req, err := c.GetRequest(url)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}
