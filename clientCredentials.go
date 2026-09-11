package sfdcclient

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sync"
)

// ErrIncompleteTokenResponse is returned when salesforce grants a token but
// omits the access token or the instance URL. Either omission would otherwise
// surface as a confusing failure a request or two later.
var ErrIncompleteTokenResponse = errors.New("salesforce token response is missing access_token or instance_url")

type clientCredentials struct {
	// Underlying HTTP client used for making all HTTP requests to salesforce
	// note that the configuration of this HTTP client will affect all HTTP
	// requests sent (including the OAuth requests)
	client http.Client

	// loginURL is the base URL the access token is requested from: the
	// organization's My Domain. It is not necessarily where the REST API is
	// served, so it is deliberately distinct from apiURL.
	loginURL     string
	clientID     string
	clientSecret string

	// apiURL is the base URL for REST API calls, taken from the instance_url
	// of the token response. Salesforce does not guarantee that it matches
	// loginURL, and for organizations where the two differ, using loginURL for
	// API calls yields 401s and 404s.
	//
	// It is cached alongside the access token it arrived with, and guarded by
	// the same mutex.
	apiURL      string
	accessToken string
	tokenMutex  *sync.RWMutex

	err      error
	errMutex *sync.RWMutex
}

// NewClientWithClientCredentials returns a client authorized against the
// salesforce organization at loginURL.
//
// This function follows the "OAuth 2.0 Client Credentials Flow for
// Server-to-Server Integration"
// see https://help.salesforce.com/s/articleView?id=xcloud.remoteaccess_oauth_client_credentials_flow.htm
//
// loginURL is a complete base URL, scheme included, and should be https: the
// token request carries the client secret in its body. The credentials belong
// to the connected app rather than to a user, so a packaged app's client ID and
// secret may be shared across organizations while loginURL varies.
//
// Constructing the client performs the token exchange, so a returned error
// means authorization failed. ctx bounds that exchange; refreshes made later
// from SendRequest are bounded by the context passed there.
//
// Salesforce does not reliably return expires_in for this flow, so the token is
// held until a call is rejected with a 401 rather than expired on a timer.
func NewClientWithClientCredentials(
	ctx context.Context,
	loginURL, clientID, clientSecret string,
	httpClient http.Client,
) (*clientCredentials, error) {
	client := clientCredentials{
		client:       httpClient,
		loginURL:     loginURL,
		clientID:     clientID,
		clientSecret: clientSecret,
		tokenMutex:   &sync.RWMutex{},
		errMutex:     &sync.RWMutex{},
	}

	if err := client.newAccessToken(ctx); err != nil {
		return &client, err
	}

	return &client, client.checkErr()
}

// newAccessToken updates the cached access token and API base URL if salesforce
// successfully grants a token.
func (c *clientCredentials) newAccessToken(ctx context.Context) error {
	var err error
	defer func() {
		c.setErr(err)
	}()

	form := url.Values{
		"grant_type":    {grantTypeClientCredentials},
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
	}

	var tokenRes AccessTokenResponse
	if tokenRes, err = requestToken(ctx, c.client, c.loginURL+oauthTokenPath, form.Encode()); err != nil {
		return err
	}

	if tokenRes.AccessToken == "" || tokenRes.Instance == "" {
		err = ErrIncompleteTokenResponse

		return err
	}

	c.tokenMutex.Lock()
	defer c.tokenMutex.Unlock()
	c.accessToken = tokenRes.AccessToken
	c.apiURL = tokenRes.Instance

	return nil
}

func (c *clientCredentials) checkErr() error {
	c.errMutex.RLock()
	defer c.errMutex.RUnlock()
	return c.err
}

func (c *clientCredentials) setErr(err error) {
	c.errMutex.Lock()
	defer c.errMutex.Unlock()
	c.err = err
}

// SendRequest sends an HTTP request as specified by its function parameters,
// relative to the API base URL salesforce reported when the token was granted.
//
// If the last authorization attempt failed, it is retried before the request is
// sent. If salesforce responds with an unauthorized 401 HTTP status code, the
// client gets a new access token and retries the request once.
func (c *clientCredentials) SendRequest(ctx context.Context, method, relURL string, headers http.Header, requestBody []byte) (int, []byte, error) {
	// Check whether the last attempt to authenticate with salesforce failed
	if c.checkErr() != nil {
		if errAuth := c.newAccessToken(ctx); errAuth != nil {
			return -1, nil, errAuth
		}
	}

	statusCode, resBody, err := c.sendRequest(ctx, method, relURL, headers, requestBody)
	if err != nil {
		// Only a salesforce API error carries a status code worth reacting to
		// see: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/errorcodes.htm
		if _, ok := err.(*APIErrs); ok && statusCode == http.StatusUnauthorized {
			// Presumably the cached access token has expired
			if errAuth := c.newAccessToken(ctx); errAuth != nil {
				return -1, nil, errAuth
			}

			// Retry the original request, against whichever API base URL and
			// token the refresh produced
			statusCode, resBody, err = c.sendRequest(ctx, method, relURL, headers, requestBody)
		}
	}

	return statusCode, resBody, err
}

func (c *clientCredentials) sendRequest(ctx context.Context, method, relURL string, headers http.Header, requestBody []byte) (int, []byte, error) {
	c.tokenMutex.RLock()
	apiURL, accessToken := c.apiURL, c.accessToken
	c.tokenMutex.RUnlock()

	return sendRequest(ctx, c.client, method, apiURL+relURL, accessToken, headers, requestBody)
}
