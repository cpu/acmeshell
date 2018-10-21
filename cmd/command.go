// Package cmd provides common command line tools for the acmeshell binaries.
package cmd

import (
	"log"
	"os"
	"os/signal"
	"syscall"
)

func FailOnError(err error, msg string) {
	// If there wasn't an error, return
	if err == nil {
		return
	}

	// Otherwise, print the error and fail
	log.Fatalf("[!] %s - %s", msg, err)
}

var signalToName = map[os.Signal]string{
	syscall.SIGTERM: "SIGTERM",
	syscall.SIGINT:  "SIGINT",
	syscall.SIGHUP:  "SIGHUP",
}

// CatchSignals catches SIGTERM, SIGINT, SIGHUP and executes a callback
// method before exiting
func CatchSignals(callback func()) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM)
	signal.Notify(sigChan, syscall.SIGINT)
	signal.Notify(sigChan, syscall.SIGHUP)

	sig := <-sigChan
	log.Printf("Caught %s", signalToName[sig])

	if callback != nil {
		callback()
	}

	log.Printf("Exiting")
	os.Exit(0)
}
