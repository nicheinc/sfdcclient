package sfdcclient

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
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

	if err = jwtBearer.newAccessToken(); err != nil {
		return &jwtBearer, err
	}

	return &jwtBearer, jwtBearer.err
}

// newAccessToken updates the cached access token if salesforce successfully grants one
// This function follows the "OAuth 2.0 JWT Bearer Flow for Server-to-Server Integration"
// see https://help.salesforce.com/articleView?id=remoteaccess_oauth_jwt_flow.htm
func (c *jwtBearer) newAccessToken() error {
	var err error
	defer func() {
		c.setErr(err)
	}()
	// Create JWT
	signedJWT, err := c.JWT()
	if err != nil {
		return err
	}

	// Request new access token from salesforce's OAuth endpoint
	oauthTokenURL := c.instanceURL + "/services/oauth2/token"
	req, err := http.NewRequest(
		http.MethodPost,
		oauthTokenURL,
		strings.NewReader(
			fmt.Sprintf("grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=%s", signedJWT),
		),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	res, err := c.client.Do(req)
	if err != nil {
		return err
	}

	resBytes, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		return err
	}

	switch res.StatusCode {
	case http.StatusOK:
		break
	case http.StatusBadRequest:
		var errRes OAuthErr
		err = json.Unmarshal(resBytes, &errRes)
		if err == nil {
			err = &errRes
		}
	default:
		err = fmt.Errorf("%s responded with an unexpected HTTP status code: %d", oauthTokenURL, res.StatusCode)
	}
	if err != nil {
		return err
	}

	var tokenRes AccessTokenResponse
	if err := json.Unmarshal(resBytes, &tokenRes); err != nil {
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

func (c jwtBearer) checkErr() error {
	c.errMutex.RLock()
	defer c.errMutex.RUnlock()
	return c.err
}

func (c jwtBearer) setErr(err error) {
	c.errMutex.Lock()
	defer c.errMutex.Unlock()
	c.err = err
	return
}

// SendRequest sends a n HTTP request as specified by its function parameters
// If the server responds with an unauthorized 401 HTTP status code, the client attempts
// to get a new authorization access token and retries the request once
func (c jwtBearer) SendRequest(ctx context.Context, method, relURL string, headers http.Header, requestBody []byte) (int, []byte, error) {
	url := c.instanceURL + relURL

	// Check if there jwtBearer had an error in the last time it tried to authenticate with salesforce
	if c.checkErr() != nil {
		errAuth := c.newAccessToken()
		if errAuth != nil {
			return -1, nil, errAuth
		}
	}
	// Issue the request to salesforce
	statusCode, resBody, err := c.sendRequest(ctx, method, url, headers, requestBody)
	if err != nil {
		// Check if the error is an actual salesforce API error
		// see: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/errorcodes.htm
		if _, ok := err.(*APIErrs); ok {
			// If the status code returned is Unauthorized (401)
			// Presumably, the current cached access token has expired,
			// hence, we attempt to update the cached access token and retry the earlier request once
			// see https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/errorcodes.htm
			if statusCode == http.StatusUnauthorized {
				errAuth := c.newAccessToken()
				if errAuth != nil {
					return -1, nil, errAuth
				}
				// Retry the original request
				statusCode, resBody, err = c.sendRequest(ctx, method, url, headers, requestBody)
				if err != nil {
					return statusCode, resBody, err
				}
			}
		}
	}

	return statusCode, resBody, err
}

func (c jwtBearer) sendRequest(ctx context.Context, method, url string, headers http.Header, requestBody []byte) (int, []byte, error) {
	var req *http.Request
	var err error
	if requestBody == nil {
		req, err = http.NewRequestWithContext(ctx, method, url, nil)
	} else {
		req, err = http.NewRequestWithContext(ctx, method, url, bytes.NewBuffer(requestBody))
	}
	if err != nil {
		return -1, nil, err
	}

	c.accessTokenMutex.RLock()
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.accessToken))
	c.accessTokenMutex.RUnlock()
	for hKey, hVals := range headers {
		for _, hVal := range hVals {
			req.Header.Add(hKey, hVal)
		}
	}

	res, err := c.client.Do(req)
	if err != nil {
		return -1, nil, err
	}
	resBytes, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		return -1, nil, err
	}

	var errs APIErrs
	switch res.StatusCode {
	// Salesforce HTTP status codes and error responses:
	// https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/errorcodes.htm
	case http.StatusOK, http.StatusCreated, http.StatusNoContent,
		http.StatusMultipleChoices, http.StatusNotModified:
		break
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden,
		http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusUnsupportedMediaType,
		http.StatusInternalServerError:
		err = json.Unmarshal(resBytes, &errs)
		if err != nil {
			// The salesforce error response body was in an unexpected and incompatible format
			return res.StatusCode, nil, err
		}
		return res.StatusCode, resBytes, &errs
	default:
		return res.StatusCode, resBytes, fmt.Errorf("unexpected HTTP status code: %d", res.StatusCode)
	}

	return res.StatusCode, resBytes, nil
}
