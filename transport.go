package sfdcclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const (
	// oauthTokenPath is the token endpoint, relative to the host the
	// authorization flow authenticates against.
	oauthTokenPath = "/services/oauth2/token"

	grantTypeJWTBearer         = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	grantTypeClientCredentials = "client_credentials"
)

// requestToken performs an OAuth token request and returns the granted token.
//
// body is the already-encoded form body, since each authorization flow sends a
// different grant type and set of credentials. A failed request is returned as
// an *OAuthErr when Salesforce describes it as one.
func requestToken(ctx context.Context, client http.Client, tokenURL, body string) (AccessTokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(body))
	if err != nil {
		return AccessTokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := client.Do(req)
	if err != nil {
		return AccessTokenResponse{}, err
	}

	resBytes, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		return AccessTokenResponse{}, err
	}

	switch res.StatusCode {
	case http.StatusOK:
		break
	case http.StatusBadRequest:
		// Only the parsed fields are surfaced, never the raw body: a token
		// request body echoed back would contain the client's credentials.
		var oauthErr OAuthErr
		if err := json.Unmarshal(resBytes, &oauthErr); err != nil {
			return AccessTokenResponse{}, err
		}

		return AccessTokenResponse{}, &oauthErr
	default:
		return AccessTokenResponse{}, fmt.Errorf("%s responded with an unexpected HTTP status code: %d", tokenURL, res.StatusCode)
	}

	var tokenRes AccessTokenResponse
	if err := json.Unmarshal(resBytes, &tokenRes); err != nil {
		return AccessTokenResponse{}, err
	}

	return tokenRes, nil
}

// sendRequestWithToken sends an authorized request to Salesforce's REST API and
// interprets the response.
//
// Every authorization flow in this package shares it: the flows differ in how
// they obtain an access token, not in how they use one. The returned status
// code is -1 when the request could not be sent or read at all. A response
// carrying a Salesforce error payload comes back as an *APIErrs.
func sendRequestWithToken(
	ctx context.Context,
	client http.Client,
	method, url, accessToken string,
	headers http.Header,
	requestBody []byte,
) (int, []byte, error) {
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

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	for hKey, hVals := range headers {
		for _, hVal := range hVals {
			req.Header.Add(hKey, hVal)
		}
	}

	res, err := client.Do(req)
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
