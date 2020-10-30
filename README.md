# sfdcclient

![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/nicheinc/sfdcclient)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/nicheinc/sfdcclient)
![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/nicheinc/sfdcclient)

sfdcclient is a golang package implementing a pseudo-wrapper of an HTTP client,
for making requests to salesforce's REST API through a connected app,
making use of the [Salesforce OAuth 2.0 JWT Bearer Flow for Server-to-Server](https://help.salesforce.com/articleView?id=remoteaccess_oauth_jwt_flow.htm&type=5)
authorization flow.

## Installation
`go get https://github.com/nicheinc/sfdcclient`

## Example usage

```go
package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/nicheinc/sfdcclient"
)

func main() {
	// Read your private key into memory
	privateKeyBytes, err := ioutil.ReadFile(os.ExpandEnv("/path/to/your/private/key/file.key"))
	if err != nil {
		log.Fatalf("Error creating logger: %s", err)
	}

	client, err := sfdcclient.NewClientWithJWTBearer(
		true, // whether the instance the client connects to, is a sandbox or not
		"https://xx123.salesforce.com",
		"your_connected_app_consumer_key",
		"username_using_the_connected_app@email_provider.com",
		privateKeyBytes,
		3*time.Second, // request timeout for the OAuth new token HTTP request (3 minute max)
		http.Client{ // underlying HTTP client making all HTTP calls
			Timeout: 5 * time.Second,
		},
	)
	if err != nil {
		log.Fatalf("Error initializing connected app salesforce client: %s", err)
	}

	url := "/services/data/v47.0/sobjects/MySObjectName/describe" // note that this is a relative URL to the salesforce instance server URL
	statusCode, resBody, err := client.SendRequest(ctx, http.MethodGet, url, nil, nil)
	if err != nil {
		log.Fatalf("Error sending salesforce request: %s", err)
	}

	fmt.Printf("\nResponse status code: %d", statusCode) // -1 if an error is returned by the SendRequest call
	fmt.Printf("\nResponse body: %s", string(resBody))
}

```