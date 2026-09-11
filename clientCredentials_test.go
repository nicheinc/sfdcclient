package sfdcclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/nicheinc/expect"
)

const (
	testClientID     = "aConnectedAppClientID"
	testClientSecret = "aConnectedAppClientSecret"
)

// tokenResponse is a token response body naming the API base URL salesforce
// should report for the granted token.
func tokenResponse(accessToken, instanceURL string) string {
	return fmt.Sprintf(`{"access_token":%q,"instance_url":%q}`, accessToken, instanceURL)
}

// roundTripFunc stands in for the transport of the http.Client the constructor
// is handed, so the constructor can be exercised against a real
// my.salesforce.com login URL - which validation requires, and no test server
// can have - without a live host.
type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// newTestClient returns a client authorized against loginURL, bypassing the
// login URL validation the constructor performs, since a test server is not
// served from a my.salesforce.com host. Validation itself is covered by
// Test_NewClientWithClientCredentials.
func newTestClient(t *testing.T, ctx context.Context, loginURL string) (*clientCredentials, error) {
	t.Helper()

	client := newClientCredentials(loginURL, testClientID, testClientSecret, *http.DefaultClient)

	return client, client.NewAccessToken(ctx)
}

// The constructor decides where the client secret is sent, so it validates
// loginURL before sending anything. The token exchange it performs afterwards
// is covered by Test_clientCredentials_NewAccessToken.
func Test_NewClientWithClientCredentials(t *testing.T) {
	type expected struct {
		nilClient     bool
		tokenRequests int
	}
	type testCase struct {
		loginURL string
		want     expected
		errCheck expect.ErrorCheck
	}
	run := func(name string, testCase testCase) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			t.Helper()

			var tokenRequests atomic.Int32

			httpClient := http.Client{
				Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					tokenRequests.Add(1)

					expect.Equal(t, req.URL.Path, oauthTokenPath)

					return &http.Response{
						StatusCode: http.StatusOK,
						Header:     http.Header{},
						Body: io.NopCloser(strings.NewReader(
							tokenResponse("aSalesforceAccessToken", "https://example.my.salesforce.com"),
						)),
					}, nil
				}),
			}

			client, err := NewClientWithClientCredentials(
				context.Background(),
				testCase.loginURL,
				testClientID,
				testClientSecret,
				httpClient,
			)
			testCase.errCheck(t, err)
			expect.Equal(t, client == nil, testCase.want.nilClient)
			expect.Equal(t, int(tokenRequests.Load()), testCase.want.tokenRequests)
		})
	}

	run("Success", testCase{
		loginURL: "https://example.my.salesforce.com",
		want:     expected{tokenRequests: 1},
		errCheck: expect.ErrorNil,
	})
	// Sandboxes and scratch orgs are served from their own subdomains, so the
	// suffix must admit more than one label in front of it.
	run("Success/Sandbox", testCase{
		loginURL: "https://example--dev.sandbox.my.salesforce.com",
		want:     expected{tokenRequests: 1},
		errCheck: expect.ErrorNil,
	})
	run("Success/ScratchOrg", testCase{
		loginURL: "https://example.scratch.my.salesforce.com",
		want:     expected{tokenRequests: 1},
		errCheck: expect.ErrorNil,
	})
	// Host names are case insensitive, so a mixed-case one is the same host.
	run("Success/MixedCaseHost", testCase{
		loginURL: "https://Example.My.Salesforce.com",
		want:     expected{tokenRequests: 1},
		errCheck: expect.ErrorNil,
	})
	run("Success/HostWithPort", testCase{
		loginURL: "https://example.my.salesforce.com:8443",
		want:     expected{tokenRequests: 1},
		errCheck: expect.ErrorNil,
	})

	// Every rejection must happen before the secret is sent anywhere, so each
	// case below expects no token request at all.
	run("Error/PlaintextHTTP", testCase{
		loginURL: "http://example.my.salesforce.com",
		want:     expected{nilClient: true},
		errCheck: expect.ErrorIs(ErrInvalidLoginURL),
	})
	run("Error/NoScheme", testCase{
		loginURL: "example.my.salesforce.com",
		want:     expected{nilClient: true},
		errCheck: expect.ErrorIs(ErrInvalidLoginURL),
	})
	run("Error/Empty", testCase{
		loginURL: "",
		want:     expected{nilClient: true},
		errCheck: expect.ErrorIs(ErrInvalidLoginURL),
	})
	run("Error/UnrelatedHost", testCase{
		loginURL: "https://attacker.example",
		want:     expected{nilClient: true},
		errCheck: expect.ErrorIs(ErrInvalidLoginURL),
	})
	// The suffix appears in the host but the host does not end with it.
	run("Error/SuffixConfusion", testCase{
		loginURL: "https://example.my.salesforce.com.attacker.example",
		want:     expected{nilClient: true},
		errCheck: expect.ErrorIs(ErrInvalidLoginURL),
	})
	// The suffix is not preceded by a label boundary.
	run("Error/SuffixWithoutLabelBoundary", testCase{
		loginURL: "https://attackermy.salesforce.com",
		want:     expected{nilClient: true},
		errCheck: expect.ErrorIs(ErrInvalidLoginURL),
	})
	// Everything before the @ is userinfo: the host is attacker.example.
	run("Error/UserinfoComponent", testCase{
		loginURL: "https://example.my.salesforce.com@attacker.example",
		want:     expected{nilClient: true},
		errCheck: expect.ErrorIs(ErrInvalidLoginURL),
	})
	// A port does not make an unrelated host salesforce's.
	run("Error/UnrelatedHostWithPort", testCase{
		loginURL: "https://attacker.example:443",
		want:     expected{nilClient: true},
		errCheck: expect.ErrorIs(ErrInvalidLoginURL),
	})
	// No organization is served from the apex, and admitting it would mean
	// matching the suffix without a label boundary.
	run("Error/ApexDomain", testCase{
		loginURL: "https://my.salesforce.com",
		want:     expected{nilClient: true},
		errCheck: expect.ErrorIs(ErrInvalidLoginURL),
	})
}

// How the token response is interpreted, exercised against a test server and
// so independent of the login URL validation the constructor performs.
func Test_clientCredentials_NewAccessToken(t *testing.T) {
	type testCase struct {
		statusCode int
		body       string
		errCheck   expect.ErrorCheck
	}
	run := func(name string, testCase testCase) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			t.Helper()

			server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				rw.WriteHeader(testCase.statusCode)
				rw.Write([]byte(testCase.body))
			}))
			defer server.Close()

			_, err := newTestClient(t, context.Background(), server.URL)
			testCase.errCheck(t, err)
		})
	}

	run("Success", testCase{
		statusCode: http.StatusOK,
		body:       tokenResponse("aSalesforceAccessToken", "https://example.my.salesforce.com"),
		errCheck:   expect.ErrorNil,
	})
	// A 2xx missing either field would otherwise fail confusingly a request or
	// two later.
	run("Error/MissingAccessToken", testCase{
		statusCode: http.StatusOK,
		body:       `{"instance_url":"https://example.my.salesforce.com"}`,
		errCheck:   expect.ErrorIs(ErrIncompleteTokenResponse),
	})
	run("Error/MissingInstanceURL", testCase{
		statusCode: http.StatusOK,
		body:       `{"access_token":"aSalesforceAccessToken"}`,
		errCheck:   expect.ErrorIs(ErrIncompleteTokenResponse),
	})
	run("Error/OAuthErrorResponse", testCase{
		statusCode: http.StatusBadRequest,
		body:       `{"error":"invalid_client","error_description":"client identifier invalid"}`,
		errCheck: expect.ErrorIs(&OAuthErr{
			Code:        "invalid_client",
			Description: "client identifier invalid",
		}),
	})
	run("Error/OAuthUnexpectedResponseFormat", testCase{
		statusCode: http.StatusBadRequest,
		body:       "bad JSON '{",
		errCheck:   expect.ErrorAs[*json.SyntaxError](),
	})
	run("Error/SalesforceBadJSON", testCase{
		statusCode: http.StatusOK,
		body:       "bad JSON '{",
		errCheck:   expect.ErrorAs[*json.SyntaxError](),
	})
	run("Error/UnexpectedOauthServerError", testCase{
		statusCode: http.StatusInternalServerError,
		errCheck:   expect.ErrorNonNil,
	})
}

// The token request is form encoded under the client_credentials grant, and
// carries the connected app's credentials as basic authentication rather than
// as body parameters.
func Test_clientCredentials_NewAccessToken_TokenRequest(t *testing.T) {
	var (
		mutex                                    sync.Mutex
		gotMethod, gotPath, gotContentType       string
		gotClientID, gotClientSecret, gotRawBody string
		gotBasicAuth                             bool
		gotForm                                  url.Values
	)

	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rawBody, err := io.ReadAll(req.Body)
		if err != nil {
			t.Errorf("Error reading request body: %v", err)
		}
		req.Body = io.NopCloser(bytes.NewReader(rawBody))
		if err := req.ParseForm(); err != nil {
			t.Errorf("Error parsing form: %v", err)
		}

		mutex.Lock()
		gotMethod = req.Method
		gotPath = req.URL.Path
		gotContentType = req.Header.Get("Content-Type")
		gotClientID, gotClientSecret, gotBasicAuth = req.BasicAuth()
		gotRawBody = string(rawBody)
		gotForm = req.PostForm
		mutex.Unlock()

		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte(tokenResponse("aSalesforceAccessToken", "https://example.my.salesforce.com")))
	}))
	defer server.Close()

	_, err := newTestClient(t, context.Background(), server.URL)
	expect.ErrorNil(t, err)

	mutex.Lock()
	defer mutex.Unlock()

	expect.Equal(t, gotMethod, http.MethodPost)
	expect.Equal(t, gotPath, oauthTokenPath)
	expect.Equal(t, gotContentType, "application/x-www-form-urlencoded")
	expect.Equal(t, gotForm.Get("grant_type"), grantTypeClientCredentials)

	expect.Equal(t, gotBasicAuth, true)
	expect.Equal(t, gotClientID, testClientID)
	expect.Equal(t, gotClientSecret, testClientSecret)

	// The credentials belong in the header alone: leaving a copy in the body
	// would forfeit the protection the header buys.
	expect.Equal(t, strings.Contains(gotRawBody, testClientSecret), false)
	expect.Equal(t, strings.Contains(gotRawBody, testClientID), false)
}

// A token request must not follow a redirect: replaying it would send the
// client secret to a host the login URL named rather than the one the caller
// addressed.
func Test_clientCredentials_NewAccessToken_DoesNotFollowRedirects(t *testing.T) {
	var redirectTargetHits atomic.Int32

	redirectTarget := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		redirectTargetHits.Add(1)

		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte(tokenResponse("aSalesforceAccessToken", "https://example.my.salesforce.com")))
	}))
	defer redirectTarget.Close()

	loginServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		http.Redirect(rw, req, redirectTarget.URL+oauthTokenPath, http.StatusTemporaryRedirect)
	}))
	defer loginServer.Close()

	_, err := newTestClient(t, context.Background(), loginServer.URL)
	expect.ErrorNonNil(t, err)
	expect.Equal(t, redirectTargetHits.Load(), 0)
}

// API requests must go to the instance URL salesforce reported, not to the
// login URL the token was obtained from. Two servers stand in for the two
// hosts: the login server should only ever be asked for a token.
func Test_clientCredentials_SendRequest_UsesInstanceURL(t *testing.T) {
	var apiHits, loginHits atomic.Int32

	apiServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		apiHits.Add(1)

		expect.Equal(t, req.URL.Path, "/services/data/v62.0/analytics/reports")
		expect.Equal(t, req.Header.Get("Authorization"), "Bearer aSalesforceAccessToken")

		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte(`[]`))
	}))
	defer apiServer.Close()

	loginServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		loginHits.Add(1)

		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte(tokenResponse("aSalesforceAccessToken", apiServer.URL)))
	}))
	defer loginServer.Close()

	client, err := newTestClient(t, context.Background(), loginServer.URL)
	expect.ErrorNil(t, err)

	statusCode, resBody, err := client.SendRequest(
		context.Background(),
		http.MethodGet,
		"/services/data/v62.0/analytics/reports",
		nil,
		nil,
	)
	expect.ErrorNil(t, err)
	expect.Equal(t, statusCode, http.StatusOK)
	expect.Equal(t, string(resBody), `[]`)

	expect.Equal(t, int(loginHits.Load()), 1)
	expect.Equal(t, int(apiHits.Load()), 1)
}

// A 401 triggers exactly one refresh and one retry, and the refreshed token
// must persist so the following request does not repeat the dance.
func Test_clientCredentials_SendRequest_RefreshesOn401(t *testing.T) {
	const (
		staleToken = "aStaleAccessToken"
		freshToken = "aFreshAccessToken"
	)

	var (
		tokensIssued, apiRequests atomic.Int32
		mutex                     sync.Mutex
		bearers                   []string
	)

	apiServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		apiRequests.Add(1)

		bearer := req.Header.Get("Authorization")
		mutex.Lock()
		bearers = append(bearers, bearer)
		mutex.Unlock()

		// The first token is already stale as far as this org is concerned.
		if bearer != "Bearer "+freshToken {
			rw.WriteHeader(http.StatusUnauthorized)
			rw.Write([]byte(`[{"message":"Session expired or invalid","errorCode":"INVALID_SESSION_ID"}]`))

			return
		}

		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte(`{"ok":true}`))
	}))
	defer apiServer.Close()

	loginServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		token := freshToken
		if tokensIssued.Add(1) == 1 {
			token = staleToken
		}

		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte(tokenResponse(token, apiServer.URL)))
	}))
	defer loginServer.Close()

	client, err := newTestClient(t, context.Background(), loginServer.URL)
	expect.ErrorNil(t, err)

	statusCode, _, err := client.SendRequest(context.Background(), http.MethodGet, "/resource", nil, nil)
	expect.ErrorNil(t, err)
	expect.Equal(t, statusCode, http.StatusOK)

	// One token for construction and one for the refresh; the rejected attempt
	// and then the retry.
	expect.Equal(t, int(tokensIssued.Load()), 2)
	expect.Equal(t, int(apiRequests.Load()), 2)

	mutex.Lock()
	expect.Equal(t, bearers, []string{"Bearer " + staleToken, "Bearer " + freshToken})
	mutex.Unlock()

	// The refreshed token persisted, so a second request neither refreshes nor
	// retries.
	statusCode, _, err = client.SendRequest(context.Background(), http.MethodGet, "/resource", nil, nil)
	expect.ErrorNil(t, err)
	expect.Equal(t, statusCode, http.StatusOK)
	expect.Equal(t, int(tokensIssued.Load()), 2)
	expect.Equal(t, int(apiRequests.Load()), 3)
}

// A client whose first authorization attempt failed re-authorizes on its next
// request rather than staying broken.
func Test_clientCredentials_SendRequest_ReauthorizesAfterFailure(t *testing.T) {
	var tokensIssued atomic.Int32

	apiServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte(`{"ok":true}`))
	}))
	defer apiServer.Close()

	loginServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// The organization is unreachable for the first attempt only.
		if tokensIssued.Add(1) == 1 {
			rw.WriteHeader(http.StatusInternalServerError)

			return
		}

		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte(tokenResponse("aSalesforceAccessToken", apiServer.URL)))
	}))
	defer loginServer.Close()

	client, err := newTestClient(t, context.Background(), loginServer.URL)
	expect.ErrorNonNil(t, err)

	statusCode, _, err := client.SendRequest(context.Background(), http.MethodGet, "/resource", nil, nil)
	expect.ErrorNil(t, err)
	expect.Equal(t, statusCode, http.StatusOK)
	expect.Equal(t, int(tokensIssued.Load()), 2)
}

// SendRequest calls NewAccessToken in two places: to recover from a prior
// authorization failure, and to refresh after a 401. Both sites return the
// authorization error without retrying the API request.
func Test_clientCredentials_SendRequest_NewAccessTokenErrors(t *testing.T) {
	type expected struct {
		statusCode int
		resBody    []byte
		tokens     int
		apiHits    int
	}
	type testCase struct {
		authErrCheck  expect.ErrorCheck
		login         func(n int, apiURL string) (statusCode int, body string)
		apiStatusCode int
		apiBody       string
		want          expected
		errCheck      expect.ErrorCheck
	}
	run := func(name string, testCase testCase) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			t.Helper()

			var tokensIssued, apiHits atomic.Int32

			apiServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				apiHits.Add(1)
				rw.WriteHeader(testCase.apiStatusCode)
				rw.Write([]byte(testCase.apiBody))
			}))
			defer apiServer.Close()

			loginServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				statusCode, body := testCase.login(int(tokensIssued.Add(1)), apiServer.URL)
				rw.WriteHeader(statusCode)
				if body != "" {
					rw.Write([]byte(body))
				}
			}))
			defer loginServer.Close()

			client, err := newTestClient(t, context.Background(), loginServer.URL)
			testCase.authErrCheck(t, err)

			statusCode, resBody, err := client.SendRequest(
				context.Background(),
				http.MethodGet,
				"/resource",
				nil,
				nil,
			)
			expect.Equal(t, statusCode, testCase.want.statusCode)
			expect.Equal(t, resBody, testCase.want.resBody)
			testCase.errCheck(t, err)
			expect.Equal(t, int(tokensIssued.Load()), testCase.want.tokens)
			expect.Equal(t, int(apiHits.Load()), testCase.want.apiHits)
		})
	}

	run("Error/ReauthorizeFails", testCase{
		authErrCheck: expect.ErrorNonNil,
		login: func(int, string) (int, string) {
			return http.StatusInternalServerError, ""
		},
		apiStatusCode: http.StatusOK,
		apiBody:       `{"ok":true}`,
		want: expected{
			statusCode: -1,
			tokens:     2,
		},
		errCheck: expect.ErrorNonNil,
	})
	run("Error/RefreshOn401Fails", testCase{
		authErrCheck: expect.ErrorNil,
		login: func(n int, apiURL string) (int, string) {
			if n == 1 {
				return http.StatusOK, tokenResponse("aStaleAccessToken", apiURL)
			}

			return http.StatusInternalServerError, ""
		},
		apiStatusCode: http.StatusUnauthorized,
		apiBody:       `[{"message":"Session expired or invalid","errorCode":"INVALID_SESSION_ID"}]`,
		want: expected{
			statusCode: -1,
			tokens:     2,
			apiHits:    1,
		},
		errCheck: expect.ErrorNonNil,
	})
}

func Test_clientCredentials_SendRequest(t *testing.T) {
	type expected struct {
		statusCode int
		resBody    []byte
	}
	type testCase struct {
		statusCode int
		body       string
		headers    http.Header
		want       expected
		errCheck   expect.ErrorCheck
	}
	run := func(name string, testCase testCase) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			t.Helper()

			apiServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				for name, values := range testCase.headers {
					expect.Equal(t, req.Header.Values(name), values)
				}

				rw.WriteHeader(testCase.statusCode)
				rw.Write([]byte(testCase.body))
			}))
			defer apiServer.Close()

			loginServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				rw.WriteHeader(http.StatusOK)
				rw.Write([]byte(tokenResponse("aSalesforceAccessToken", apiServer.URL)))
			}))
			defer loginServer.Close()

			client, err := newTestClient(t, context.Background(), loginServer.URL)
			expect.ErrorNil(t, err)

			statusCode, resBody, err := client.SendRequest(
				context.Background(),
				http.MethodGet,
				"/resource",
				testCase.headers,
				nil,
			)

			expect.Equal(t, statusCode, testCase.want.statusCode)
			expect.Equal(t, resBody, testCase.want.resBody)
			testCase.errCheck(t, err)
		})
	}

	run("Success", testCase{
		statusCode: http.StatusOK,
		body:       `{"ok":true}`,
		want: expected{
			statusCode: http.StatusOK,
			resBody:    []byte(`{"ok":true}`),
		},
		errCheck: expect.ErrorNil,
	})
	run("Success/CopiesCallerHeaders", testCase{
		statusCode: http.StatusOK,
		body:       `{"ok":true}`,
		headers:    http.Header{"Headername": []string{"value1", "value2"}},
		want: expected{
			statusCode: http.StatusOK,
			resBody:    []byte(`{"ok":true}`),
		},
		errCheck: expect.ErrorNil,
	})
	run("Error/SalesforceAPIError", testCase{
		statusCode: http.StatusNotFound,
		body:       `[{"message":"The requested resource does not exist","errorCode":"NOT_FOUND"}]`,
		want: expected{
			statusCode: http.StatusNotFound,
			resBody:    []byte(`[{"message":"The requested resource does not exist","errorCode":"NOT_FOUND"}]`),
		},
		errCheck: expect.ErrorIs(&APIErrs{
			APIErr{
				Message: "The requested resource does not exist",
				ErrCode: "NOT_FOUND",
			},
		}),
	})
	run("Error/UnexpectedStatusCode", testCase{
		statusCode: http.StatusTeapot,
		body:       "I'm a teapot",
		want: expected{
			statusCode: http.StatusTeapot,
			resBody:    []byte("I'm a teapot"),
		},
		errCheck: expect.ErrorNonNil,
	})
}

// The token request body carries the client secret, so an error describing a
// rejected token request must never repeat it back.
func Test_clientCredentials_TokenErrorOmitsClientSecret(t *testing.T) {
	// A gateway that echoes the request body is the realistic way this leaks.
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Errorf("Error reading request body: %v", err)
		}

		rw.WriteHeader(http.StatusBadRequest)
		rw.Write(body)
	}))
	defer server.Close()

	_, err := newTestClient(t, context.Background(), server.URL)
	expect.ErrorNonNil(t, err)

	if strings.Contains(err.Error(), testClientSecret) {
		t.Errorf("Error contains the client secret: %v", err)
	}
}

// The context passed to the constructor bounds the token exchange.
func Test_clientCredentials_ContextAppliesToTokenRequest(t *testing.T) {
	var tokensIssued atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		tokensIssued.Add(1)

		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte(tokenResponse("aSalesforceAccessToken", "https://example.my.salesforce.com")))
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := newTestClient(t, ctx, server.URL)
	expect.ErrorIs(context.Canceled)(t, err)
	expect.Equal(t, int(tokensIssued.Load()), 0)
}
