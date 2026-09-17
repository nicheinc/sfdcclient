package sfdcclient

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type jwtBearer struct {
	// Underlying HTTP client used for making all HTTP requests to salesforce
	// note that the configuration of this HTTP client will affect all HTTP
	// requests sent (including the OAuth requests)
	client http.Client

	// URL of server where the salesforce organization lives
	instanceURL string

	// Variables needed for the generation and signing of the JWT token
	rsaPrivateKey *rsa.PrivateKey
	consumerKey   string
	username      string
	authServerURL string
	tokenDuration time.Duration

	// Cached access token issued by Salesforce
	accessToken      string
	accessTokenMutex *sync.RWMutex

	err      error
	errMutex *sync.RWMutex
}

func NewClientWithJWTBearer(sandbox bool, instanceURL, consumerKey, username string, privateKey []byte, tokenDuration time.Duration, httpClient http.Client) (*jwtBearer, error) {
	jwtBearer := jwtBearer{
		client:           httpClient,
		instanceURL:      instanceURL,
		consumerKey:      consumerKey,
		username:         username,
		accessTokenMutex: &sync.RWMutex{},
		tokenDuration:    tokenDuration,
		errMutex:         &sync.RWMutex{},
	}

	baseSFURL := "https://%s.salesforce.com"
	if sandbox {
		jwtBearer.authServerURL = fmt.Sprintf(baseSFURL, "test")
	} else {
		jwtBearer.authServerURL = fmt.Sprintf(baseSFURL, "login")
	}

	var err error
	if jwtBearer.rsaPrivateKey, err = jwt.ParseRSAPrivateKeyFromPEM(privateKey); err != nil {
		return nil, err
	}

	// The constructor has no context of its own to thread into the initial
	// token request. Refreshes made later from SendRequest use the caller's.
	if err = jwtBearer.newAccessToken(context.Background()); err != nil {
		return &jwtBearer, err
	}

	return &jwtBearer, jwtBearer.err
}

// newAccessToken updates the cached access token if salesforce successfully grants one
// This function follows the "OAuth 2.0 JWT Bearer Flow for Server-to-Server Integration"
// see https://help.salesforce.com/articleView?id=remoteaccess_oauth_jwt_flow.htm
func (c *jwtBearer) newAccessToken(ctx context.Context) error {
	var err error
	defer func() {
		c.setErr(err)
	}()

	// Create JWT
	var signedJWT string
	if signedJWT, err = c.JWT(); err != nil {
		return err
	}

	// The assertion is base64url encoded, so it carries no characters that
	// require escaping, and the grant type is sent unescaped as salesforce has
	// always received it.
	body := fmt.Sprintf("grant_type=%s&assertion=%s", grantTypeJWTBearer, signedJWT)

	var tokenRes AccessTokenResponse
	if tokenRes, err = requestToken(ctx, c.client, c.instanceURL+oauthTokenPath, body, nil); err != nil {
		return err
	}

	c.accessTokenMutex.Lock()
	defer c.accessTokenMutex.Unlock()
	c.accessToken = tokenRes.AccessToken

	return nil
}

func (c *jwtBearer) JWT() (string, error) {
	// Create JWT
	jwt.MarshalSingleStringAsArray = false
	token := jwt.NewWithClaims(
		jwt.SigningMethodRS256,
		jwt.RegisteredClaims{
			Issuer:    c.consumerKey,
			Audience:  []string{c.authServerURL},
			Subject:   c.username,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(c.tokenDuration).UTC()),
		},
	)
	// Sign JWT with the private key
	return token.SignedString(c.rsaPrivateKey)
}

func (c *jwtBearer) checkErr() error {
	c.errMutex.RLock()
	defer c.errMutex.RUnlock()
	return c.err
}

func (c *jwtBearer) setErr(err error) {
	c.errMutex.Lock()
	defer c.errMutex.Unlock()
	c.err = err
}

// SendRequest sends a n HTTP request as specified by its function parameters
// If the server responds with an unauthorized 401 HTTP status code, the client attempts
// to get a new authorization access token and retries the request once
func (c *jwtBearer) SendRequest(ctx context.Context, method, relURL string, headers http.Header, requestBody []byte) (int, []byte, error) {
	url := c.instanceURL + relURL

	// Check if there jwtBearer had an error in the last time it tried to authenticate with salesforce
	if c.checkErr() != nil {
		errAuth := c.newAccessToken(ctx)
		if errAuth != nil {
			return -1, nil, errAuth
		}
	}
	// Issue the request to salesforce
	statusCode, resBody, err := c.sendRequest(ctx, method, url, headers, requestBody)
	// Only a salesforce API error carries a status code worth reacting to
	// see: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/errorcodes.htm
	if _, ok := errors.AsType[*APIErrs](err); ok && statusCode == http.StatusUnauthorized {
		// Presumably, the current cached access token has expired,
		// hence, we attempt to update the cached access token and retry the earlier request once
		errAuth := c.newAccessToken(ctx)
		if errAuth != nil {
			return -1, nil, errAuth
		}
		// Retry the original request
		statusCode, resBody, err = c.sendRequest(ctx, method, url, headers, requestBody)
		if err != nil {
			return statusCode, resBody, err
		}
	}

	return statusCode, resBody, err
}

func (c *jwtBearer) sendRequest(ctx context.Context, method, url string, headers http.Header, requestBody []byte) (int, []byte, error) {
	c.accessTokenMutex.RLock()
	accessToken := c.accessToken
	c.accessTokenMutex.RUnlock()

	return sendRequestWithToken(ctx, c.client, method, url, accessToken, headers, requestBody)
}
