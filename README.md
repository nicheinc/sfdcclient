# sfdcclient

![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/nicheinc/sfdcclient)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/nicheinc/sfdcclient)
[![Go Report Card](https://goreportcard.com/badge/github.com/nicheinc/sfdcclient)](https://goreportcard.com/report/github.com/nicheinc/sfdcclient)
![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/nicheinc/sfdcclient)

sfdcclient is a golang package implementing a pseudo-wrapper of an HTTP client,
for making requests to salesforce's REST API through a connected app.

Two server-to-server authorization flows are supported, one constructor each:

| Constructor                      | Flow                                                                                                                                      |
| -------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `NewClientWithJWTBearer`         | [OAuth 2.0 JWT Bearer](https://help.salesforce.com/articleView?id=remoteaccess_oauth_jwt_flow.htm&type=5)                                 |
| `NewClientWithClientCredentials` | [OAuth 2.0 Client Credentials](https://help.salesforce.com/s/articleView?id=xcloud.remoteaccess_oauth_client_credentials_flow.htm&type=5) |

## Installation

`go get https://github.com/nicheinc/sfdcclient`

## Example usage

### JWT Bearer

```go
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/nicheinc/sfdcclient"
)

func main() {
	// Read your private key into memory
	privateKeyBytes, err := os.ReadFile(os.ExpandEnv("/path/to/your/private/key/file.key"))
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
	statusCode, resBody, err := client.SendRequest(context.Background(), http.MethodGet, url, nil, nil)
	if err != nil {
		log.Fatalf("Error sending salesforce request: %s", err)
	}

	fmt.Printf("\nResponse status code: %d", statusCode) // -1 if an error is returned by the SendRequest call
	fmt.Printf("\nResponse body: %s", string(resBody))
}

```

### Client Credentials

Unlike the JWT Bearer flow, the credentials belong to the connected app rather
than to a user, so a packaged app's client ID and secret can be shared across
organizations while the login URL varies per organization.

Note the two distinct hosts: the token is requested from the organization's My
Domain, and API requests then go to the `instance_url` salesforce returns with
the token. The two are not always the same host, and the client handles the
switch for you.

Both hosts are validated to be an `https` Salesforce My Domain (a host ending
in `.my.salesforce.com`) before use. An invalid login URL is rejected as
`ErrInvalidLoginURL` without making a request; an invalid `instance_url` from
the token response is rejected the same way. Check for it with `errors.Is`.

```go
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/nicheinc/sfdcclient/v2"
)

func main() {
	ctx := context.Background()

	// Constructing the client performs the token exchange, so an error here
	// means authorization failed. The context bounds that exchange.
	client, err := sfdcclient.NewClientWithClientCredentials(
		ctx,
		"https://example.my.salesforce.com", // the organization's My Domain
		"your_connected_app_client_id",
		"your_connected_app_client_secret",
		http.Client{ // underlying HTTP client making all HTTP calls
			Timeout: 5 * time.Second,
		},
	)
	if err != nil {
		log.Fatalf("Error initializing connected app salesforce client: %s", err)
	}

	url := "/services/data/v62.0/analytics/reports" // relative to the instance URL
	statusCode, resBody, err := client.SendRequest(ctx, http.MethodGet, url, nil, nil)
	if err != nil {
		log.Fatalf("Error sending salesforce request: %s", err)
	}

	fmt.Printf("\nResponse status code: %d", statusCode) // -1 if an error is returned by the SendRequest call
	fmt.Printf("\nResponse body: %s", string(resBody))
}
```
