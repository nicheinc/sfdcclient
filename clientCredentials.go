package sfdcclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// ErrIncompleteTokenResponse is returned when salesforce grants a token but
// omits the access token or the instance URL. Either omission would otherwise
// surface as a confusing failure a request or two later.
var ErrIncompleteTokenResponse = errors.New("salesforce token response is missing access_token or instance_url")

// ErrInvalidLoginURL is returned by NewClientWithClientCredentials when
// loginURL is not an https URL on the my.salesforce.com domain. Errors
// describing why wrap it, so callers can match on it with errors.Is.
var ErrInvalidLoginURL = errors.New("login URL must be an https URL whose host ends in " + salesforceDomainSuffix)

// salesforceDomainSuffix is the domain every salesforce My Domain is a
// subdomain of, including sandboxes (.sandbox.my.salesforce.com) and scratch
// orgs (.scratch.my.salesforce.com).
const salesforceDomainSuffix = "my.salesforce.com"

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
// loginURL is a complete base URL, scheme included, naming the organization's
// My Domain. It decides where the client secret is sent, and the credentials
// belong to the connected app rather than to a user: for a packaged app one
// client ID and secret authorize every organization that installed it, so a
// loginURL naming a host that is not salesforce's would exfiltrate a
// credential for all of them rather than merely fail to connect. It is
// therefore validated, and an invalid one is returned as an
// ErrInvalidLoginURL without any request being made.
//
// Constructing the client performs the token exchange, so a returned error
// means either validation or authorization failed. ctx bounds that exchange;
// refreshes made later from SendRequest are bounded by the context passed
// there.
//
// Salesforce does not reliably return expires_in for this flow, so the token is
// held until a call is rejected with a 401 rather than expired on a timer.
func NewClientWithClientCredentials(
	ctx context.Context,
	loginURL, clientID, clientSecret string,
	httpClient http.Client,
) (*clientCredentials, error) {
	if err := validateLoginURL(loginURL); err != nil {
		return nil, err
	}

	client := newClientCredentials(loginURL, clientID, clientSecret, httpClient)

	if err := client.NewAccessToken(ctx); err != nil {
		return client, err
	}

	return client, client.checkErr()
}

// newClientCredentials assembles a client without contacting salesforce, so
// that validation and the token exchange remain separable.
func newClientCredentials(loginURL, clientID, clientSecret string, httpClient http.Client) *clientCredentials {
	return &clientCredentials{
		client:       httpClient,
		loginURL:     loginURL,
		clientID:     clientID,
		clientSecret: clientSecret,
		tokenMutex:   &sync.RWMutex{},
		errMutex:     &sync.RWMutex{},
	}
}

// validateLoginURL reports whether loginURL is an https URL on a salesforce My
// Domain host.
//
// The host is matched by suffix on the parsed hostname rather than on the
// string, since a string match would accept hosts that merely contain the
// suffix: "example.my.salesforce.com.attacker.example" ends elsewhere,
// "https://example.my.salesforce.com@attacker.example" names the host after
// the @, and neither is salesforce.
func validateLoginURL(loginURL string) error {
	// The parse error quotes the input, which may carry credentials of its own
	// in a userinfo component, so it is not wrapped.
	parsed, err := url.Parse(loginURL)
	if err != nil {
		return fmt.Errorf("%w: not a parseable URL", ErrInvalidLoginURL)
	}

	if parsed.Scheme != "https" {
		return fmt.Errorf("%w: scheme is %q, not https", ErrInvalidLoginURL, parsed.Scheme)
	}

	// A userinfo component makes the text before the @ look like the host, and
	// salesforce has no use for one.
	if parsed.User != nil {
		return fmt.Errorf("%w: %s names a userinfo component", ErrInvalidLoginURL, parsed.Redacted())
	}

	// Hostname strips any port, and host names are case insensitive.
	hostname := strings.ToLower(parsed.Hostname())
	if !strings.HasSuffix(hostname, "."+salesforceDomainSuffix) {
		return fmt.Errorf("%w: host is %q", ErrInvalidLoginURL, parsed.Host)
	}

	return nil
}

// NewAccessToken requests an access token from the organization's My Domain,
// updating the cached access token and API base URL if salesforce grants one.
//
// The client authorizes itself on construction and re-authorizes as needed
// from SendRequest, so calling this is only necessary to refresh deliberately.
func (c *clientCredentials) NewAccessToken(ctx context.Context) error {
	var err error
	defer func() {
		c.setErr(err)
	}()

	// The credentials are sent as basic authentication rather than as body
	// parameters, leaving only the grant type in the body.
	form := url.Values{
		"grant_type": {grantTypeClientCredentials},
	}
	credentials := basicAuth{
		clientID:     c.clientID,
		clientSecret: c.clientSecret,
	}

	var tokenRes AccessTokenResponse
	if tokenRes, err = requestToken(ctx, c.client, c.loginURL+oauthTokenPath, form.Encode(), &credentials); err != nil {
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
		if errAuth := c.NewAccessToken(ctx); errAuth != nil {
			return -1, nil, errAuth
		}
	}

	statusCode, resBody, err := c.sendRequest(ctx, method, relURL, headers, requestBody)
	// Only a salesforce API error carries a status code worth reacting to
	// see: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/errorcodes.htm
	if _, ok := errors.AsType[*APIErrs](err); ok && statusCode == http.StatusUnauthorized {
		// Presumably the cached access token has expired
		if errAuth := c.NewAccessToken(ctx); errAuth != nil {
			return -1, nil, errAuth
		}

		// Retry the original request, against whichever API base URL and
		// token the refresh produced
		statusCode, resBody, err = c.sendRequest(ctx, method, relURL, headers, requestBody)
	}

	return statusCode, resBody, err
}

func (c *clientCredentials) sendRequest(ctx context.Context, method, relURL string, headers http.Header, requestBody []byte) (int, []byte, error) {
	c.tokenMutex.RLock()
	apiURL, accessToken := c.apiURL, c.accessToken
	c.tokenMutex.RUnlock()

	return sendRequestWithToken(ctx, c.client, method, apiURL+relURL, accessToken, headers, requestBody)
}
