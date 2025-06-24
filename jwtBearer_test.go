package sfdcclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/nicheinc/expect"
)

var (
	testRSAPrivateKeyBytes []byte
	testRSAPrivateKey      *rsa.PrivateKey
)

func init() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("Error building test private key %v", err))
	}
	pemEncoded := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	var b bytes.Buffer
	err = pem.Encode(&b, pemEncoded)
	if err != nil {
		panic(fmt.Sprintf("Error building test private key %v", err))
	}
	testRSAPrivateKeyBytes = b.Bytes()

	testRSAPrivateKey, err = jwt.ParseRSAPrivateKeyFromPEM(testRSAPrivateKeyBytes)
	if err != nil {
		panic(fmt.Sprintf("Error parsing private key file to an RSA private key %v", err))
	}
}

func Test_NewClientWithJWTBearer(t *testing.T) {
	type args struct {
		isProd        bool
		instanceURL   string
		consumerKey   string
		username      string
		privateKey    []byte
		tokenDuration time.Duration
	}
	type testCase struct {
		name     string
		args     args
		want     *jwtBearer
		errCheck expect.ErrorCheck
		wantErr  bool
	}
	run := func(name string, testCase testCase) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			t.Helper()
			_, err := NewClientWithJWTBearer(
				testCase.args.isProd,
				testCase.args.instanceURL,
				testCase.args.consumerKey,
				testCase.args.username,
				testCase.args.privateKey,
				testCase.args.tokenDuration,
				*http.DefaultClient,
			)
			testCase.errCheck(t, err)
		})
	}

	testTokenSuccessServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte(`{"access_token":"aSalesforceAccessToken"}`))
		return
	}))
	defer testTokenSuccessServer.Close()

	testTokenErrorServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusBadRequest)
		rw.Write([]byte(`{"error":"aSalesforceError"}`))
	}))
	defer testTokenErrorServer.Close()

	run("Error/ParseRSAPrivateKeyFromPEM", testCase{
		args: args{
			isProd:        true,
			privateKey:    nil,
			tokenDuration: 10 * time.Second,
		},
		errCheck: expect.ErrorNonNil,
	})
	run("Error/GettingToken", testCase{
		args: args{
			instanceURL:   testTokenErrorServer.URL,
			privateKey:    testRSAPrivateKeyBytes,
			tokenDuration: 10 * time.Second,
		},
		want: &jwtBearer{
			client:           http.Client{},
			instanceURL:      testTokenErrorServer.URL,
			rsaPrivateKey:    testRSAPrivateKey,
			accessTokenMutex: &sync.RWMutex{},
			authServerURL:    testTokenErrorServer.URL,
			errMutex:         &sync.RWMutex{},
		},
		errCheck: expect.ErrorIs(&OAuthErr{
			Code:        "aSalesforceError",
			Description: "",
		}),
	})
	run("Success", testCase{
		args: args{
			isProd:        true,
			instanceURL:   testTokenSuccessServer.URL,
			privateKey:    testRSAPrivateKeyBytes,
			tokenDuration: 10 * time.Second,
		},
		want: &jwtBearer{
			client:           http.Client{},
			instanceURL:      testTokenSuccessServer.URL,
			username:         "my@email.com",
			rsaPrivateKey:    testRSAPrivateKey,
			accessTokenMutex: &sync.RWMutex{},
			authServerURL:    testTokenErrorServer.URL,
			accessToken:      "aSalesforceAccessToken",
			errMutex:         &sync.RWMutex{},
		},
		errCheck: expect.ErrorNil,
	})
}

func Test_jwtBearer_newAccessToken(t *testing.T) {
	type fields struct {
		client           http.Client
		instanceURL      string
		rsaPrivateKey    *rsa.PrivateKey
		consumerKey      string
		username         string
		authServerURL    string
		accessToken      string
		accessTokenMutex *sync.RWMutex
		errMutex         *sync.RWMutex
	}
	type testCase struct {
		name     string
		fields   fields
		errCheck expect.ErrorCheck
	}
	run := func(name string, testCase testCase) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			t.Helper()
			c := &jwtBearer{
				client:           testCase.fields.client,
				instanceURL:      testCase.fields.instanceURL,
				rsaPrivateKey:    testCase.fields.rsaPrivateKey,
				consumerKey:      testCase.fields.consumerKey,
				username:         testCase.fields.username,
				authServerURL:    testCase.fields.authServerURL,
				accessToken:      testCase.fields.accessToken,
				accessTokenMutex: testCase.fields.accessTokenMutex,
				errMutex:         testCase.fields.errMutex,
			}
			err := c.newAccessToken()
			testCase.errCheck(t, err)
		})
	}

	testServerSuccess := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte(`{"access_token":"aSalesforceAccessToken"}`))
	}))
	defer testServerSuccess.Close()

	testServerBadJSON := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("bad JSON '{"))
	}))
	defer testServerBadJSON.Close()

	testServerBadReq := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusBadRequest)
		rw.Write([]byte(`{
			"error":"someSalesforceError",
			"error_description":"outOfMana"	
		}`))
	}))
	defer testServerBadReq.Close()

	testServerBadReqBadJson := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusBadRequest)
		rw.Write([]byte("bad JSON '{"))
	}))
	defer testServerBadReqBadJson.Close()

	testServerErr := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusInternalServerError)
	}))
	defer testServerErr.Close()

	{
		run("SalesforceBadJSONError", testCase{
			fields: fields{
				client:           http.Client{},
				username:         "my@email.com",
				instanceURL:      testServerBadJSON.URL,
				rsaPrivateKey:    testRSAPrivateKey,
				accessTokenMutex: &sync.RWMutex{},
				errMutex:         &sync.RWMutex{},
			},
			errCheck: expect.ErrorAs[*json.SyntaxError](),
		})
		run("ErrorSigningJWTWithPrivateKey", testCase{
			fields: fields{
				client:           http.Client{},
				username:         "my@email.com",
				instanceURL:      testServerSuccess.URL,
				accessTokenMutex: &sync.RWMutex{},
				rsaPrivateKey: &rsa.PrivateKey{
					PublicKey: rsa.PublicKey{
						N: big.NewInt(3),
						E: 123456789,
					},
					D: big.NewInt(1),
				},
				errMutex: &sync.RWMutex{},
			},
			errCheck: expect.ErrorIs(rsa.ErrMessageTooLong),
		})
		run("OauthErrorResponse", testCase{
			fields: fields{
				client:           http.Client{},
				username:         "my@email.com",
				instanceURL:      testServerBadReq.URL,
				rsaPrivateKey:    testRSAPrivateKey,
				accessTokenMutex: &sync.RWMutex{},
				errMutex:         &sync.RWMutex{},
			},
			errCheck: expect.ErrorIs(&OAuthErr{
				Code:        "someSalesforceError",
				Description: "outOfMana",
			}),
		})
		run("OauthUnexpectedResponseFormat", testCase{
			fields: fields{
				client:           http.Client{},
				username:         "my@email.com",
				instanceURL:      testServerBadReqBadJson.URL,
				rsaPrivateKey:    testRSAPrivateKey,
				accessTokenMutex: &sync.RWMutex{},
				errMutex:         &sync.RWMutex{},
			},
			errCheck: expect.ErrorAs[*json.SyntaxError](),
		})
		run("UnexpectedOauthServerError", testCase{
			fields: fields{
				client:           http.Client{},
				username:         "my@email.com",
				instanceURL:      testServerErr.URL,
				rsaPrivateKey:    testRSAPrivateKey,
				accessTokenMutex: &sync.RWMutex{},
				errMutex:         &sync.RWMutex{},
			},
			errCheck: expect.ErrorNonNil,
		})
		run("Success", testCase{
			fields: fields{
				client:           http.Client{},
				username:         "my@email.com",
				instanceURL:      testServerSuccess.URL,
				rsaPrivateKey:    testRSAPrivateKey,
				accessTokenMutex: &sync.RWMutex{},
				errMutex:         &sync.RWMutex{},
			},
			errCheck: expect.ErrorNil,
		})
	}
}

func Test_jwtBearer_sendRequest(t *testing.T) {
	type args struct {
		ctx         context.Context
		method      string
		url         string
		headers     http.Header
		requestBody []byte
	}
	type expected struct {
		statusCode int
		resBody    []byte
	}
	type testCase struct {
		args     args
		want     expected
		errCheck expect.ErrorCheck
	}
	run := func(name string, testCase testCase) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			t.Helper()
			c := &jwtBearer{
				client:           http.Client{},
				rsaPrivateKey:    testRSAPrivateKey,
				accessTokenMutex: &sync.RWMutex{},
			}

			statusCode, resBody, err := c.sendRequest(
				testCase.args.ctx,
				testCase.args.method,
				testCase.args.url,
				testCase.args.headers,
				testCase.args.requestBody,
			)

			expect.Equal(t, statusCode, testCase.want.statusCode)
			expect.Equal(t, resBody, testCase.want.resBody)
			testCase.errCheck(t, err)
		})
	}

	testServerResBody := []byte(`hello world`)
	testServerStatusCode := http.StatusOK
	testServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(testServerStatusCode)
		rw.Write(testServerResBody)
	}))
	defer testServer.Close()

	testServerTeapotResBody := []byte("I'm a teapot")
	testServerTeapotStatusCode := http.StatusTeapot
	testServerTeapot := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(testServerTeapotStatusCode)
		rw.Write(testServerTeapotResBody)
	}))
	defer testServerTeapot.Close()

	testServerBadResFmt := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte(`this_is_in_an_un-understandable_format`))
	}))
	defer testServerBadResFmt.Close()

	testServerErrBody := []byte(`
	[
		{
			"message": "Session expired or invalid",
			"errorCode": "INVALID_SESSION_ID"
		}
	]
	`)
	testServerErrStatusCode := http.StatusInternalServerError
	var testServerErrSfErr APIErrs
	json.Unmarshal(testServerErrBody, &testServerErrSfErr)
	testServerErr := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(testServerErrStatusCode)
		rw.Write(testServerErrBody)
	}))
	defer testServerErr.Close()

	run("NewRequestWithNilBody/Error", testCase{
		args: args{
			ctx: context.Background(),
		},
		want: expected{
			statusCode: -1,
		},
		errCheck: expect.ErrorNonNil,
	})
	run("NewRequestWithBody/Error", testCase{
		args: args{
			ctx:         context.Background(),
			requestBody: []byte("test"),
		},
		want: expected{
			statusCode: -1,
		},
		errCheck: expect.ErrorNonNil,
	})
	run("UnexpectedStatusCode", testCase{
		args: args{
			ctx:     context.Background(),
			method:  http.MethodGet,
			url:     testServerTeapot.URL,
			headers: http.Header{"headerName": []string{"value1", "value2"}},
		},
		want: expected{
			statusCode: testServerTeapotStatusCode,
			resBody:    testServerTeapotResBody,
		},
		errCheck: expect.ErrorNonNil,
	})
	run("NilBodySuccess", testCase{
		args: args{
			ctx:     context.Background(),
			method:  http.MethodGet,
			url:     testServer.URL,
			headers: http.Header{"headerName": []string{"value1", "value2"}},
		},
		want: expected{
			statusCode: testServerStatusCode,
			resBody:    testServerResBody,
		},
		errCheck: expect.ErrorNil,
	})
	run("ErroneousStatusCode/UnexpectedResponseFormat", testCase{
		args: args{
			ctx:    context.Background(),
			method: http.MethodGet,
			url:    testServerBadResFmt.URL,
		},
		want: expected{
			statusCode: http.StatusInternalServerError,
		},
		errCheck: expect.ErrorAs[*json.SyntaxError](),
	})
	run("ErroneousStatusCode", testCase{
		args: args{
			ctx:    context.Background(),
			method: http.MethodGet,
			url:    testServerErr.URL,
		},
		want: expected{
			statusCode: testServerErrStatusCode,
			resBody:    testServerErrBody,
		},
		errCheck: expect.ErrorIs(&APIErrs{
			APIErr{
				Message: "Session expired or invalid",
				ErrCode: "INVALID_SESSION_ID",
			},
		}),
	})
	run("Success", testCase{
		args: args{
			ctx:     context.Background(),
			method:  http.MethodGet,
			url:     testServer.URL,
			headers: http.Header{"headerName": []string{"value1", "value2"}},
		},
		want: expected{
			statusCode: testServerStatusCode,
			resBody:    testServerResBody,
		},
		errCheck: expect.ErrorNil,
	})
}

func Test_jwtBearer_SendRequest(t *testing.T) {
	type args struct {
		method      string
		relURL      string
		headers     http.Header
		requestBody []byte
	}
	type fields struct {
		instanceURL   string
		consumerKey   string
		username      string
		authServerURL string
		accessToken   string
		err           error
	}
	type expected struct {
		statusCode int
		resBody    []byte
	}
	type testCase struct {
		args     args
		fields   fields
		want     expected
		errCheck expect.ErrorCheck
	}

	run := func(name string, testCase testCase) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			t.Helper()
			c := &jwtBearer{
				client:           http.Client{},
				instanceURL:      testCase.fields.instanceURL,
				rsaPrivateKey:    testRSAPrivateKey,
				consumerKey:      testCase.fields.consumerKey,
				username:         testCase.fields.username,
				authServerURL:    testCase.fields.authServerURL,
				accessToken:      testCase.fields.accessToken,
				accessTokenMutex: &sync.RWMutex{},
				errMutex:         &sync.RWMutex{},
				err:              testCase.fields.err,
			}
			statusCode, resBody, err := c.SendRequest(
				context.Background(),
				testCase.args.method,
				testCase.args.relURL,
				testCase.args.headers,
				testCase.args.requestBody,
			)

			expect.Equal(t, statusCode, testCase.want.statusCode)
			expect.Equal(t, resBody, testCase.want.resBody)
			testCase.errCheck(t, err)
		})
	}

	testAccessToken := "token_williams"

	testServerBadResFmtStatusCode := http.StatusInternalServerError
	testServerBadResFmtBody := []byte(`this_is_in_an_un-understandable_format`)
	testServerBadResFmt := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(testServerBadResFmtStatusCode)
		rw.Write(testServerBadResFmtBody)
	}))
	defer testServerBadResFmt.Close()

	testServerGetNewTokenStatusCode := http.StatusInternalServerError
	testServerGetNewTokenBody1 := []byte(`
	[
		{
			"message": "Session expired or invalid",
			"errorCode": "INVALID_SESSION_ID"
		}
	]
	`)
	testServerGetNewTokenBody2 := []byte(`
	[
		{
			"errorCode":"SERVER_ERROR"
		}
	]
	`)
	var testServerGetNewTokenErr APIErrs
	json.Unmarshal(testServerGetNewTokenBody2, &testServerGetNewTokenErr)
	testServerGetNewToken := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.URL != nil && req.URL.Path == "/services/oauth2/token" {
			rw.WriteHeader(http.StatusOK)
			rw.Write([]byte(fmt.Sprintf(`{"access_token":"%s"}`, testAccessToken)))
			return
		}
		if req.Header.Get("Authorization") != fmt.Sprintf("Bearer %s", testAccessToken) {
			rw.WriteHeader(http.StatusUnauthorized)
			rw.Write(testServerGetNewTokenBody1)
			return
		}
		rw.WriteHeader(testServerGetNewTokenStatusCode)
		rw.Write(testServerGetNewTokenBody2)
	}))
	defer testServerGetNewToken.Close()

	testServerNewTokenErrStatusCode := http.StatusUnauthorized
	testServerNewTokenErrBody := []byte(`
		{
			"error": "invalid_grant",
			"error_description": "invalid authorization code"
		}
	`)
	var testServerNewTokenErrErr OAuthErr
	json.Unmarshal(testServerNewTokenErrBody, &testServerNewTokenErrErr)
	testServerNewTokenErr := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.URL != nil && req.URL.Path == "/services/oauth2/token" {
			rw.WriteHeader(http.StatusBadRequest)
			rw.Write(testServerNewTokenErrBody)
			return
		}
		rw.WriteHeader(testServerNewTokenErrStatusCode)
		rw.Write([]byte(`
			[
				{
					"errorCode":"INVALID_SESSION_ID"
				}
			]
		`))
	}))
	defer testServerNewTokenErr.Close()

	testServerUnauthorizedNewTokenSuccessStatusCode := http.StatusOK
	testServerUnauthorizedNewTokenSuccessBody := []byte(`{"hello":"world"}`)
	testServerUnauthorizedNewTokenSuccess := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.URL != nil && req.URL.Path == "/services/oauth2/token" {
			rw.WriteHeader(http.StatusOK)
			rw.Write([]byte(fmt.Sprintf(`{"access_token":"%s"}`, testAccessToken)))
			return
		}
		if req.Header.Get("Authorization") != fmt.Sprintf("Bearer %s", testAccessToken) {
			rw.WriteHeader(http.StatusUnauthorized)
			rw.Write([]byte(`
			[
				{
					"errorCode":"INVALID_SESSION_ID"
				}
			]
			`))
			return
		}
		rw.WriteHeader(testServerUnauthorizedNewTokenSuccessStatusCode)
		rw.Write(testServerUnauthorizedNewTokenSuccessBody)
	}))
	defer testServerUnauthorizedNewTokenSuccess.Close()

	run("jwtBearerWithError/NewTokenError", testCase{
		fields: fields{
			instanceURL: testServerNewTokenErr.URL,
			err:         errors.New("something bad happened"),
		},
		want: expected{
			statusCode: -1,
		},
		errCheck: expect.ErrorIs(&testServerNewTokenErrErr),
	})
	run("jwtBearerWithError/NewTokenSuccess", testCase{
		fields: fields{
			instanceURL: testServerUnauthorizedNewTokenSuccess.URL,
			err:         errors.New("something bad happened"),
		},
		want: expected{
			statusCode: testServerUnauthorizedNewTokenSuccessStatusCode,
			resBody:    testServerUnauthorizedNewTokenSuccessBody,
		},
		errCheck: expect.ErrorNil,
	})
	run("sendRequest/Error", testCase{
		fields: fields{
			instanceURL: testServerBadResFmt.URL,
		},
		want: expected{
			statusCode: testServerBadResFmtStatusCode,
		},
		errCheck: expect.ErrorAs[*json.SyntaxError](),
	})
	run("ExpiredToken/NewTokenError", testCase{
		fields: fields{
			instanceURL: testServerNewTokenErr.URL,
		},
		args: args{
			method: http.MethodGet,
			relURL: "/something",
		},
		want: expected{
			statusCode: -1,
		},
		errCheck: expect.ErrorIs(&testServerNewTokenErrErr),
	})
	run("Unauthorized/NewTokenSuccess/Request/Error", testCase{
		fields: fields{
			instanceURL: testServerGetNewToken.URL,
		},
		args: args{
			method: http.MethodGet,
			relURL: "/something",
		},
		want: expected{
			statusCode: testServerGetNewTokenStatusCode,
			resBody:    testServerGetNewTokenBody2,
		},
		errCheck: expect.ErrorIs(&testServerGetNewTokenErr),
	})
	run("Unauthorized/NewTokenError", testCase{
		fields: fields{
			instanceURL: testServerNewTokenErr.URL,
		},
		args: args{
			method: http.MethodGet,
			relURL: "/something",
		},
		want: expected{
			statusCode: -1,
		},
		errCheck: expect.ErrorIs(&testServerNewTokenErrErr),
	})
	run("Unauthorized/NewToken/Success", testCase{
		fields: fields{
			instanceURL: testServerUnauthorizedNewTokenSuccess.URL,
		},
		args: args{
			method: http.MethodGet,
			relURL: "/something",
		},
		want: expected{
			statusCode: testServerUnauthorizedNewTokenSuccessStatusCode,
			resBody:    testServerUnauthorizedNewTokenSuccessBody,
		},
		errCheck: expect.ErrorNil,
	})
}
