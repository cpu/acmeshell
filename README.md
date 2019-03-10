# ACMEShell

An interactive shell designed for [ACME][acme] client/server
developers to use for tests, day to day tasks, and exploring the protocol.
ACMEShell Supports both interactive and non-interactive usage.

---

[![Build Status](https://travis-ci.com/cpu/acmeshell.svg?branch=master)](https://travis-ci.com/cpu/acmeshell)
[![GolangCI](https://golangci.com/badges/github.com/cpu/acmeshell.svg)](https://golangci.com/r/github.com/cpu/acmeshell)
[![Go Report Card](https://goreportcard.com/badge/github.com/cpu/acmeshell)](https://goreportcard.com/report/github.com/cpu/acmeshell)

---

* [Warning](#warning)
* [Quick-start](#quick-start)
* [Features](#features)
* [The ACME Playset](#the-acme-playset)
* [Usage](#usage)
  * [Server Options](#server-options)
  * [Account Management](#account-management)
  * [Key Management](#key-management)
  * [Workflow](#workflow)
* [Tips and Tricks](#tips-and-tricks)
* [TODO](#todo)

---

## Warning

ACMEShell is **not** a shell script based ACME client, it's a shell environment
for ACME. If you're looking for a shell script ACME client you should try
[acme.sh][acme.sh] instead.

ACMEShell is designed for **developers** - not server administrators. Do not use
ACMEShell to issue or renew production certificates. Do not write automation
around ACMEShell to manage real certificates and keypairs! Instead, use
a real ACME client (like [Certbot][certbot]) or a real ACME library (like
[Lego][lego]).

ACMEShell was coded in short bursts of infrequent free time. The code quality is
not my best work. Cleanup pull requests are welcome. If something seems strange
it's probably because I threw it together in a rush while trying to make
progress on my real task (likely debugging [Boulder][boulder]).

## Quick-start

1. Pick an [ACMEShell release][releases] and download the `.tar.gz` archive for
   your architecture (for example `Linux_x86_64.tar.gz`):

       wget https://github.com/cpu/acmeshell/releases/download/v0.0.1/acmeshell_0.0.1_Linux_x86_64.tar.gz

1. Extract the archive and change into the extracted directory:

       tar xf acmeshell_*.tar.gz
       cd acmeshell*

1. Make the `acmeshell` program executable:

       chmod +x acmeshell

1. Run the `acmeshell` program:

       ./acmeshell

That's it! You should find yourself in an ACMEShell session with the [Let's
Encrypt][letsencrypt] "ACME v2" [staging environment][staging] ACME server.
A new ACME account will have automatically been created for your session. You're
ready to go!

## Features

* Convenient interactive shell supporting auto-completion of commands and menu
  selection of ACME objects.
* Non-interactive usage suitable for scripts and automated tests.
* High level commands like `newOrder`, `getAuthz`, `solve` for interacting with
  an ACME server quickly and easily.
* Low level commands like `sign`, `post`, and `get` to have fine-grain control
  over protocol messages to exercise new features or reproduce corner-case
  bugs.
* Powerful templating support for convenient manual construction of
  authenticated protocol messages.
* Create, save/load and switch between many ACME accounts in one session.
* Create, save/load, and use named private keys for ACME messages (CSRs, key
  rollovers, etc).
* Built-in challenge server for returning HTTP-01 and TLS-ALPN-01 challenge
  responses (also supports using an external `pebble-challtestsrv`).
* Built-in mock DNS server for DNS-01 challenges and directing
  HTTP-01/TLS-ALPN-01 requests to the built-in challenge server.
* Supports logging all HTTP requests/responses, JWS objects, and to-be-signed
  JSON messages to give full protocol visibility.
* Utility functions for generating CSRs and working with Base64URL encoded data.

## The ACME Playset

If you would like to experiment with an end-to-end ACME environment where you
can fake DNS entries and issue untrusted test certificates for domains you don't
control ACMEShell integrates out of the box with [Pebble][pebble].

To get started install [Docker][docker] and [Docker Compose][docker-compose] and
then run the following command in the `acmeshell` repo:

       docker-compose up

This will start a `pebble` container configured to use a second
`pebble-challtestsrv` container for DNS.

To connect ACMEShell to the Pebble container and use the `pebble-challtestsrv`
container for challenge responses run:

       acmeshell -pebble -postAsGet=true -challsrv=http://localhost:8055

## Usage

### Server Options

#### Directory

The most important option is `-directory` command line flag. If none is provided
ACMEShell will use the [Let's Encrypt][letsencrypt] ACME v2 [staging
environment][staging] server directory address.

#### ACME Server HTTPS CA Certificate

Many test ACME servers (Pebble included) serve their API over an HTTPS address
with a certificate that isn't signed by a root in the system's trusted CA store.
You can specify a custom root CA certificate to use to validate the ACME
server's HTTPS certificate with the `-ca` flag.

#### Pebble Defaults

If you specify `-pebble` then [Pebble][pebble] defaults are assumed and the
`-directory` address will be `https://localhost:14000/dir` to match the Pebble
default and the `-ca` flag will be
`$GOPATH/src/github.com/letsencrypt/pebble/test/certs/pebble.minica.pem`. If you
do not have Pebble installed in your `$GOPATH` you may need to download the
`pebble.minica.pem` file from the Pebble repo and specify its location with the
`-ca` flag.

#### POST-AS-GET

ACMEShell supports using [POST-AS-GET][postasget] to fetch resources, or the
legacy unauthenticated GET method. By default ACMEShell uses unauthenticated
GETs but this will likely change in the near future.

If you are using Pebble or another ACME server that enforces the use of
authenticated POST-AS-GET requests you will want to specify `-postASGet=true` to
make ACMEShell always use POST-AS-GET in higher level commands.

### Account Management

ACMEShell supports multiple ACME accounts. One account is considered "active" at
a time and is used by the higher level commands.

#### Command Line Flags

By default without changing any command line flags `acmeshell` will try to load
an active ACME account at startup from `acmeshell.account.json` in the current
directory.

If that file doesn't, ACMEShell will create a new account with the ACME server
and save it to `acmeshell.account.json` to use the next time `acmeshell` starts.

You can disable `acmeshell` automatically creating an account if one doesn't
exist by using `-autoregister=false`. In this case if the
`acmeshell.account.json` file doesn't exist `acmeshell` will still startup but
there will be no active account and many commands will not work until one is
created with `newAccount`.

By default no contact address is provided when automatically creating an account
at startup. Use `-contact=some-email@address.com` to set a contact address when
creating an auto-registered account.

#### Creating More Accounts

To create new accounts above and beyond the autoregistered account use the
`newAccount` command.

```
Usage of newAccount:
  -contacts string
    	Comma separated list of contact emails
  -json string
    	Optional filepath to a JSON save file for the account
  -keyID string
    	Key ID for existing key (empty to generate new key)
  -switch
    	Switch to the new account after creating it (default true)
```

For example to create and switch to a new ACME account with two contact
addresses that will be persisted to `/tmp/foo.bar.account.json` run:

       newAccount -contacts=foo@example.com,bar@example.com \
          -json=/tmp/foo.bar.account.json \

If you wanted to create the account but **not** switch to it, add
`-switch=false`.

#### Listing Accounts

You can list the available accounts with the `accounts` command:

```
Usage of accounts:
  -showContact
    	Print ACME account contact info (default true)
  -showID
    	Print ACME account IDs (default true)
```

#### Switching Accounts

You can switch the active account with the `switchAccount` command:

```
Usage of switchAccount:
  -account int
    	account number to switch to. leave blank to pick interactively (default -1)
```

The `-account` index corresponds to the output from `accounts`.

#### Save Active Account Data

After creating `newOrder`'s it can be useful to save the active account's state
to the `-json` file that was provided when it was created with `newAccount` (or
the `-account` file that it was loaded from by `acmeshell`). To do so use the
`saveAccount` command.

```
Usage of saveAccount:
  -json string
    	Filepath to a JSON save file for the account. If empty the -account argument is used
```

#### Load accounts

To load an account from JSON that isn't present in the `accounts` output (e.g.
because it was perhaps created in a different session) use the `loadAccount`
command:

```
Usage of loadAccount:
  -switch
    	Switch to the account after loading it (default true)
```

### Key Management

ACMEShell supports managing multiple private keys and giving them human
identifiable labels to make it easy to use them for other ACME
commands/messages.

#### Account keys

By default all accounts that are created by ACMEShell get an account private key
automatically created for them with a label equal to ID the server gave the
account.

For example if my `-autoregister` account was given the ID
`"https://localhost:14000/my-account/1"` by the ACME server then ACMEShell will
have created a private key with the label
`"https://localhost:14000/my-account/1"` with the account private key.

#### Creating additional keys

Some commands (e.g. `finalize`, `csr`) will automatically generate random
private keys as required. If you need to control the private key that is used
you can create additional private keys and reference them by ID in other
commands.

Use the `newKey` command to create a new private key:

```
Usage of newKey:
  -id string
    	ID for the new key
  -jwk
    	Print JWK output (default true)
  -path string
    	Path to write PEM private key to
  -pem
    	Print PEM output
```

#### Viewing a key

Use the `viewKey` command to interactively list keys and display the chosen
private key's public JWK and Thumbprint.

#### Load keys

Load an existing private key (in PEM representation) from a file using the
`loadKey` command:

```
Usage of loadKey:
  -id string
    	ID for the key
```

### Workflow

#### Interactive and non-interactive

The high level commands let you quickly perform ACME operations without having
to manually construct any messages. Most of these commands support two methods
of use:

* if not enough arguments are provided they can be used interactively, letting
  you choose objects from a menu.
* if enough arguments are provided to unambiguously perform the operation it
  will be done non-interactively

#### Order indexes

Each order created with the `newOrder` command is assigned an order index to
make it easy to reference in other commands. The first order will be index `0`,
the second `1`, and so on. These indexes are **account specific**. If you change
the active account with `switchAccount` the order indexes will change to be
based on the orders that the new account has created.

#### High level commands

* **newAccount** - create an account with the server.
* **getAccount** - fetch the active account's details from the server.
* **rollover** - change the active account's key to a new key.
* **newOrder** - create an order resource.
* **getOrder** - fetch an order resource.
* **getAuthz** - fetch an authorization resource.
* **getChall** - fetch a challenge resource.
* **solve** - solve a challenge associated with an authz from an order.
* **poll** - poll a resource until its in a specific state.
* **finalize** - finalize an order by POSTing a CSR.
* **getCert** - get an order's certificate resource.

Here's an example of using the high level commands non-interactively to complete
an order issuance:

       newOrder -identifiers=threeletter.agency
       getOrder -order=0
       getAuthz -order=0 -identifier=threeletter.agency
       getChall -order=0 -identifier=threeletter.agency -type=http-01
       solve -order=0 -identifier=threeletter.agency -challengeType=http-01
       poll -order=0
       finalize -order=0
       poll -order=0 -status=valid
       getCert -order=0

#### Low Level Commands

* **b64url** - BASE64URL encoding/decoding utility.
* **challSrv** - add/remove challenge responses from the built-in challenge
  server or the `-challsrv` provided on the command line.
* **csr** - utility for creating a CSR for specified names or for the
  identifiers in a specified order with a random private key or another
  ACMEShell key.
* **get** - HTTP GET an arbitrary URL. E.g. a terms of service URL.
* **jwsDecode** - Decode a JSON JWS and its BASE64URL encoded fields.
* **post** - HTTP POST an arbitrary payload to an arbitrary URL.
* **sign** - create a JWS for a provided message with the active account key or
  another ACMEShell key.

##### Templating

Many of the low level commands let you template values based on ACMEShell
objects. There are several templating functions and variables available:

* `account` - a variable for the current account ID.
* `order <order index>` - a function that returns the order with the given
  index.
* `authz <order> <identifier>` - a function that returns the authorization from
  the given order for the given identifier.
* `chal <authz> <type>` - a function that returns the challenge of the given
  type from the given authorization.
* `key <id>` - a function that returns the ACMEShell private key with the given
  ID.
* `csr <order> <key>` - a function that returns a BASE64URL encoded CSR created
  for the identifiers from the given order and signed with the given private key.

Here's an example that shows how templating can be used with some of the low
level commands:

       echo See the active account's JWK
       viewKey {{ account }}
       echo Change the active account contact info
       post -body='{"contact":["mailto:new@example.com"]}' {{ account }}
       echo Get an order
       get {{ (order 0) }}
       echo Get some authz details
       get {{ (authz (order 0) \"example.com\") }}
       echo Get some challenge details
       get {{ (chal (authz (order 0) \"example.com\") \"tls-alpn-01\") }}
       echo POST a CSR to the first order finalize URL
       post -body='{"csr":"{{ (csr (order 0) (key "example.key")) }}"}' {{ (order 0).Finalize }}

See `docs/example.script.txt` for a complete non-interactive demo using
templating.

## Tips and tricks

* Input lines starting with a `#` character are ignored by ACMEShell and can be
  used to comment output or scripts.
* ACMEShell supports [many "readline" shortcuts][readline]. (E.g. `CTRL-A` to go
  to the beginning of the line, `CTRL-L` to clear the screen).
* ACMEShell can read non-interactive input from STDIN, or from a file using the
  `-in` argument. This is useful to run `acmeshell` in the [delve
  debugger][delve]:

       dlv debug github.com/cpu/acmeshell/cmd/acmeshell -- -pebble -in docs/example.script.txt

## TODO

* Support RSA account keys (lol).
* `revoke` high level command for revocation.
* `keyAuth` low level command for making key authorizations for a specific
  challenge with a specific key.
* support for exiting on a command failure (e.g. for integration tests).
* so much cleanup...
* some unit tests would be swell.
* better docs.
* polish - checking for consistency between commands (e.g. `-type` vs
  `-challengeType`).

[acme]: https://tools.ietf.org/html/draft-ietf-acme-acme-18
[certbot]: https://certbot.org
[lego]: https://github.com/xenolf/lego
[acme.sh]: https://github.com/neilpang/acme.sh
[boulder]: https://github.com/letsencrypt/boulder
[releases]: https://github.com/cpu/acmeshell/releases
[letsencrypt]: https://letsencrypt.org
[staging]: https://letsencrypt.org/docs/staging-environment/
[pebble]: https://github.com/letsencrypt/pebble
[postasget]: https://community.letsencrypt.org/t/acme-v2-scheduled-deprecation-of-unauthenticated-resource-gets/74380
[docker]: https://docs.docker.com/install/
[docker-compose]: https://docs.docker.com/compose/install/
[readline]: https://github.com/chzyer/readline/blob/master/doc/shortcut.md
[delve]: https://github.com/go-delve/delve
