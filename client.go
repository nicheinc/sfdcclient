package sfdcclient

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"go.uber.org/zap"
)

type salesforceClient struct {
	// Underlying http client used for making all HTTP requests to salesforce
	// note that the configuration of this HTTP client will affect all HTTP
	// requests done by this struct (including the OAuth requests)
	client http.Client

	// URL of server where the salesforce organization lives
	// instanceURL *url.URL
	instanceURL string

	// Variables needed for the generation and signing of the JWT token
	rsaPrivateKey   *rsa.PrivateKey
	consumerKey     string
	username        string
	authServer      string
	tokenExpTimeout time.Duration

	// Authentication token issued by Salesforce
	accessToken      string
	accessTokenMutex *sync.RWMutex

	logger *zap.Logger
}

func NewClientWithJWTBearer(sandbox bool, instance, consumerKey, username string, privateKey []byte, tokenExpTimeout time.Duration, httpClient http.Client, logger *zap.Logger) (Client, error) {
	appClient := salesforceClient{
		client:           httpClient,
		instanceURL:      fmt.Sprintf("https://%s.salesforce.com", instance),
		consumerKey:      consumerKey,
		username:         username,
		accessTokenMutex: &sync.RWMutex{},
		logger:           logger,
	}

	baseSFURL := "https://%s.salesforce.com"
	if sandbox {
		appClient.authServer = fmt.Sprintf(baseSFURL, "test")
	} else {
		appClient.authServer = fmt.Sprintf(baseSFURL, "login")
	}

	var err error

	if appClient.rsaPrivateKey, err = jwt.ParseRSAPrivateKeyFromPEM(privateKey); err != nil {
		logger.Error("Error parsing private key file to an RSA private key", zap.Error(err))
		return nil, err
	}

	if err = appClient.setNewAccessToken(); err != nil {
		logger.Error("Error getting access token from salesforce", zap.Error(err))
	}

	fmt.Println(appClient.accessToken)

	return &appClient, nil
}

// setNewAccessToken updates the client's accessToken if salesforce successfully grants one
// This function implements "OAuth 2.0 JWT Bearer Flow for Server-to-Server Integration"
// see https://help.salesforce.com/articleView?id=remoteaccess_oauth_jwt_flow.htm
func (c *salesforceClient) setNewAccessToken() error {
	// Create JWT
	token := jwt.NewWithClaims(
		jwt.SigningMethodRS256,
		jwt.StandardClaims{
			Issuer:    c.consumerKey,
			Audience:  c.authServer,
			Subject:   c.username,
			ExpiresAt: time.Now().Add(c.tokenExpTimeout).UTC().Unix(),
		},
	)
	// Sign JWT with the private key
	signedJWT, err := token.SignedString(c.rsaPrivateKey)
	if err != nil {
		return err
	}

	// Request new access token from salesforce's OAuth endpoint
	req, err := http.NewRequest(
		"POST",
		c.instanceURL+"/services/oauth2/token",
		strings.NewReader(
			fmt.Sprintf("grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=%s", signedJWT),
		),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	res, err := c.client.Do(req)
	if err != nil {
		return err
	}

	resBytes, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		c.logger.Error("Error reading response body of access token request", zap.Error(err))
		return err
	}

	var tokenRes NewTokenResponse
	if err := json.Unmarshal(resBytes, &tokenRes); err != nil {
		c.logger.Error("Error parsing response body from salesforce", zap.Error(err))
		return err
	}

	// If salesforce responds with an error, return it
	if tokenRes.NewTokenOAuthErr != nil {
		return tokenRes.NewTokenOAuthErr
	}

	// Update the our access token
	c.accessTokenMutex.Lock()
	c.accessToken = tokenRes.AccessToken
	c.accessTokenMutex.Unlock()

	return nil
}

// SendRequest sends a n HTTP request as specified by its function parameters
// If the server responds with an unauthorized 401 HTTP status code, the client attempts
// to get a new authorization access token and retries the same request one more time
func (c salesforceClient) SendRequest(ctx context.Context, method, relURL string, headers http.Header, requestBody []byte) (int, []byte, error) {
	url := c.instanceURL + relURL
	var err error

	// Issue the request to salesforce
	statusCode, resBody, err := c.sendRequest(ctx, method, url, headers, requestBody)
	if err != nil {
		// Check if the error came from salesforce's API
		if _, ok := err.(*ErrorObjects); ok {
			// If the status code returned is Unauthorized (401)
			// Presumably, the current client's access token we have has expired,
			// hence, we attempt to update the client's access token and retry the request once
			// see https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/errorcodes.htm
			if statusCode == http.StatusUnauthorized {
				c.logger.Error("Current salesforce access token expired or invalid, attempting to get a new one", zap.Error(err))
				err = c.setNewAccessToken()
				if err != nil {
					c.logger.Error("Getting new access token from salesforce", zap.Error(err))
					return statusCode, nil, err
				}
				statusCode, resBody, err = c.sendRequest(ctx, method, url, headers, requestBody)
				if err != nil {
					return statusCode, nil, err
				}
			}
		} else {
			return statusCode, nil, err
		}
	}

	return statusCode, resBody, nil
}

func (c salesforceClient) sendRequest(ctx context.Context, method, url string, headers http.Header, requestBody []byte) (int, []byte, error) {
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
	resBytes, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		return -1, nil, err
	}

	var errs ErrorObjects
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
			c.logger.Error("Unexpected salesforce response format",
				zap.Int("statusCode", res.StatusCode),
				zap.String("responseBody", string(resBytes)),
			)
			return res.StatusCode, nil, err
		}
		return res.StatusCode, nil, &errs
	default:
		c.logger.Error("Salesforce returned an unexpected HTTP status code",
			zap.Int("statusCode", res.StatusCode),
			zap.String("responseBody", string(resBytes)),
		)
		return res.StatusCode, nil, fmt.Errorf("unexpected HTTP status code: %d", res.StatusCode)
	}

	return res.StatusCode, resBytes, nil
}
