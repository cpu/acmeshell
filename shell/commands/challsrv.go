package commands

import (
	"encoding/json"
	"fmt"

	acmenet "github.com/cpu/acmeshell/net"
)

// ChallengeServer is an interface for the parts of
// github.com/letsencrypt/challtestsrv.ChallengeServer that acmeshell uses.
type ChallengeServer interface {
	// Start/stop the challenge server
	Run()
	Shutdown()

	// HTTP-01 challenge add/remove
	AddHTTPOneChallenge(token string, keyAuth string)
	DeleteHTTPOneChallenge(token string)

	// DNS-01 challenge add/remove
	AddDNSOneChallenge(host string, keyAuth string)
	DeleteDNSOneChallenge(host string)

	// TLS-ALPN-01 challenge add/remove
	AddTLSALPNChallenge(host string, keyAuth string)
	DeleteTLSALPNChallenge(host string)

	// Default IPv4/IPv6
	SetDefaultDNSIPv4(addr string)
	SetDefaultDNSIPv6(addr string)

	// Mock DNS A records
	AddDNSARecord(host string, addresses []string)
	DeleteDNSARecord(host string)

	// Mock DNS AAAA records
	AddDNSAAAARecord(host string, addresses []string)
	DeleteDNSAAAARecord(host string)
}

type remoteChallengeServer struct {
	address string
	net     *acmenet.ACMENet
}

func NewRemoteChallengeServer(addr string) (ChallengeServer, error) {
	net, err := acmenet.New("")
	if err != nil {
		return nil, err
	}
	return remoteChallengeServer{
		address: addr,
		net:     net,
	}, nil
}

func (srv remoteChallengeServer) url(path string) string {
	return fmt.Sprintf("%s/%s", srv.address, path)
}

func mustMarshal(ob interface{}) []byte {
	result, _ := json.Marshal(ob)
	return result
}

func (srv remoteChallengeServer) Run() {
	// NOP - there's nothing to run.
}

func (srv remoteChallengeServer) Shutdown() {
	// NOP - there's nothing to shutdown.
}

func (srv remoteChallengeServer) AddHTTPOneChallenge(token string, keyAuth string) {
	path := "add-http01"
	req := struct {
		Token   string
		Content string
	}{
		Token:   token,
		Content: keyAuth,
	}
	r, _ := srv.net.PostRequest(srv.url(path), mustMarshal(req))
	_, _ = srv.net.Do(r)
}

func (srv remoteChallengeServer) DeleteHTTPOneChallenge(token string) {
	path := "del-http01"
	req := struct {
		Token string
	}{
		Token: token,
	}
	r, _ := srv.net.PostRequest(srv.url(path), mustMarshal(req))
	_, _ = srv.net.Do(r)
}

func (srv remoteChallengeServer) AddDNSOneChallenge(host string, keyAuth string) {
	path := "set-txt"
	req := struct {
		Host  string
		Value string
	}{
		Host:  "_acme-challenge." + host + ".",
		Value: keyAuth,
	}
	r, _ := srv.net.PostRequest(srv.url(path), mustMarshal(req))
	_, _ = srv.net.Do(r)
}

func (srv remoteChallengeServer) DeleteDNSOneChallenge(host string) {
	path := "clear-txt"
	req := struct {
		Host string
	}{
		Host: host,
	}
	r, _ := srv.net.PostRequest(srv.url(path), mustMarshal(req))
	_, _ = srv.net.Do(r)
}

func (srv remoteChallengeServer) AddTLSALPNChallenge(host string, keyAuth string) {
	path := "add-tlsalpn01"
	req := struct {
		Host    string
		Content string
	}{
		Host:    host,
		Content: keyAuth,
	}
	r, _ := srv.net.PostRequest(srv.url(path), mustMarshal(req))
	_, _ = srv.net.Do(r)
}

func (srv remoteChallengeServer) DeleteTLSALPNChallenge(host string) {
	path := "del-tlsalpn01"
	req := struct {
		Host string
	}{
		Host: host,
	}
	r, _ := srv.net.PostRequest(srv.url(path), mustMarshal(req))
	_, _ = srv.net.Do(r)
}

func (srv remoteChallengeServer) SetDefaultDNSIPv4(addr string) {
	path := "set-default-ipv4"
	req := struct {
		IP string
	}{
		IP: addr,
	}
	r, _ := srv.net.PostRequest(srv.url(path), mustMarshal(req))
	_, _ = srv.net.Do(r)
}

func (srv remoteChallengeServer) SetDefaultDNSIPv6(addr string) {
	path := "set-default-ipv6"
	req := struct {
		IP string
	}{
		IP: addr,
	}
	r, _ := srv.net.PostRequest(srv.url(path), mustMarshal(req))
	_, _ = srv.net.Do(r)
}

func (srv remoteChallengeServer) AddDNSARecord(host string, addresses []string) {
	path := "add-a"
	req := struct {
		Host      string
		Addresses []string
	}{
		Host:      host,
		Addresses: addresses,
	}
	r, _ := srv.net.PostRequest(srv.url(path), mustMarshal(req))
	_, _ = srv.net.Do(r)
}

func (srv remoteChallengeServer) DeleteDNSARecord(host string) {
	path := "clear-a"
	req := struct {
		Host string
	}{
		Host: host,
	}
	r, _ := srv.net.PostRequest(srv.url(path), mustMarshal(req))
	_, _ = srv.net.Do(r)
}

func (srv remoteChallengeServer) AddDNSAAAARecord(host string, addresses []string) {
	path := "add-aaaa"
	req := struct {
		Host      string
		Addresses []string
	}{
		Host:      host,
		Addresses: addresses,
	}
	r, _ := srv.net.PostRequest(srv.url(path), mustMarshal(req))
	_, _ = srv.net.Do(r)
}

func (srv remoteChallengeServer) DeleteDNSAAAARecord(host string) {
	path := "clear-aaaa"
	req := struct {
		Host string
	}{
		Host: host,
	}
	r, _ := srv.net.PostRequest(srv.url(path), mustMarshal(req))
	_, _ = srv.net.Do(r)
}
