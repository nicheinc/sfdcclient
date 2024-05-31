package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/nicheinc/sfdcclient"
	"github.com/peterbourgon/ff/v3"
)

func main() {

	var (
		sandbox              bool
		salesforceInstanceID string
		privateKeyFile       string
		consumerKey          string
		username             string
	)

	flag.BoolVar(&sandbox, "sandbox", false, "Whether the instance the client connects to, is a sandbox or not")
	flag.StringVar(&salesforceInstanceID, "salesforce.instanceID", "", "Salesforce instance URL")
	flag.StringVar(&privateKeyFile, "salesforce.app.cert.privateKey", "", "Path to the private key file")
	flag.StringVar(&consumerKey, "salesforce.app.consumerKey", "", "Connected app consumer key")
	flag.StringVar(&username, "salesforce.app.username", "", "Username using the connected app")

	if err := ff.Parse(flag.CommandLine, os.Args[1:], ff.WithEnvVarNoPrefix()); err != nil {
		log.Fatalf("Error parsing flags: %s", err)
	}

	// Read your private key into memory
	privateKeyBytes, err := os.ReadFile(privateKeyFile)
	if err != nil {
		log.Fatalf("Error reading private key: %s", err)
	}

	client, err := sfdcclient.NewClientWithJWTBearer(
		sandbox,              // whether the instance the client connects to, is a sandbox or not
		salesforceInstanceID, // the salesforce instance URL
		consumerKey,          // the connected app consumer key
		username,             // the username using the connected app
		privateKeyBytes,
		3*time.Second, // request timeout for the OAuth new token HTTP request (3 minute max)
		http.Client{ // underlying HTTP client making all HTTP calls
			Timeout: 5 * time.Second,
		},
	)
	if err != nil {
		log.Fatalf("Error initializing connected app salesforce client: %s", err)
	}

	jwt, err := client.JWT()
	if err != nil {
		log.Fatalf("Error getting JWT: %s", err)
	}
	fmt.Printf("%s\n", jwt)
}
