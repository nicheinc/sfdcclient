# sfdcclient

sfdcclient is a golang package implementing a pseudo-wrapper to an HTTP client, for making
making requests to salesforce's REST API through a connected app,
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
		"your_connected_add_consumer_key",
		"username_using_the_connected_app@email_provider.com",
		privateKeyBytes,
		3*time.Second, // request timeout for the OAuth new token HTTP request
		http.Client{ // underlying HTTP client making all HTTP calls
			Timeout: 5 * time.Second,
		},
	)
	if err != nil {
		log.Fatalf("Error initializing connected app salesforce client: %s", err)
	}

	url := "/services/data/v47.0/sobjects/MySObjectName/describe"
	statusCode, resBody, err := client.SendRequest(ctx, http.MethodGet, url, nil, nil)
	if err != nil {
		log.Fatalf("Error sending salesforce request: %s", err)
	}

	fmt.Printf("\nResponse status code: %d", statusCode) // -1 if an error is also returned by the SendRequest call
	fmt.Printf("\nResponse body: %s", string(resBody))
}

```