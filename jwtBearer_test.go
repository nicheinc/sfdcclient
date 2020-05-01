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
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
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

func TestNewClientWithJWTBearer(t *testing.T) {
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

	type args struct {
		isProd        bool
		instanceURL   string
		consumerKey   string
		username      string
		privateKey    []byte
		tokenDuration time.Duration
	}
	tests := []struct {
		name    string
		args    args
		want    *jwtBearer
		wantErr bool
	}{
		{
			name: "Error/TokenDurationTooSmall",
			args: args{
				tokenDuration: 1 * time.Second,
			},
			wantErr: true,
		},
		{
			name: "Error/ParseRSAPrivateKeyFromPEM",
			args: args{
				isProd:        true,
				privateKey:    nil,
				tokenDuration: 10 * time.Second,
			},
			wantErr: true,
		},
		{
			name: "ErrorGettingToken",
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
			},
			wantErr: true,
		},
		{
			name: "Success",
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
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewClientWithJWTBearer(tt.args.isProd, tt.args.instanceURL, tt.args.consumerKey, tt.args.username, tt.args.privateKey, tt.args.tokenDuration, *http.DefaultClient)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewClientWithJWTBearer() error = %+v, wantErr %+v", err != nil, tt.wantErr)
			}
		})
	}
}

func TestClient_newAccessToken(t *testing.T) {
	testServerSuccess := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte(`{"access_token":"aSalesforceAccessToken"}`))
	}))
	defer testServerSuccess.Close()

	var aux interface{}
	badJSONErr := json.Unmarshal([]byte("bad JSON '{"), aux)
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

	type fields struct {
		client           http.Client
		instanceURL      string
		rsaPrivateKey    *rsa.PrivateKey
		consumerKey      string
		username         string
		authServerURL    string
		accessToken      string
		accessTokenMutex *sync.RWMutex
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr error
	}{
		{
			name: "SalesforceBadJSONError",
			fields: fields{
				client:           http.Client{},
				username:         "my@email.com",
				instanceURL:      testServerBadJSON.URL,
				rsaPrivateKey:    testRSAPrivateKey,
				accessTokenMutex: &sync.RWMutex{},
			},
			wantErr: badJSONErr,
		},
		{
			name: "ErrorSigningJWTWithPrivateKey",
			fields: fields{
				client:           http.Client{},
				username:         "my@email.com",
				instanceURL:      testServerSuccess.URL,
				accessTokenMutex: &sync.RWMutex{},
				rsaPrivateKey:    &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: big.NewInt(1)}},
			},
			wantErr: rsa.ErrMessageTooLong,
		},
		{
			name: "OauthErrorResponse",
			fields: fields{
				client:           http.Client{},
				username:         "my@email.com",
				instanceURL:      testServerBadReq.URL,
				rsaPrivateKey:    testRSAPrivateKey,
				accessTokenMutex: &sync.RWMutex{},
			},
			wantErr: &OAuthErr{
				Code:        "someSalesforceError",
				Description: "outOfMana",
			},
		},
		{
			name: "OauthUnexpectedResponseFormat",
			fields: fields{
				client:           http.Client{},
				username:         "my@email.com",
				instanceURL:      testServerBadReqBadJson.URL,
				rsaPrivateKey:    testRSAPrivateKey,
				accessTokenMutex: &sync.RWMutex{},
			},
			wantErr: badJSONErr,
		},
		{
			name: "UnexpectedOauthServerError",
			fields: fields{
				client:           http.Client{},
				username:         "my@email.com",
				instanceURL:      testServerErr.URL,
				rsaPrivateKey:    testRSAPrivateKey,
				accessTokenMutex: &sync.RWMutex{},
			},
			wantErr: fmt.Errorf("%s responded with an unexpected HTTP status code: %d",
				testServerErr.URL+"/services/oauth2/token",
				http.StatusInternalServerError,
			),
		},
		{
			name: "Success",
			fields: fields{
				client:           http.Client{},
				username:         "my@email.com",
				instanceURL:      testServerSuccess.URL,
				rsaPrivateKey:    testRSAPrivateKey,
				accessTokenMutex: &sync.RWMutex{},
			},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &jwtBearer{
				client:           tt.fields.client,
				instanceURL:      tt.fields.instanceURL,
				rsaPrivateKey:    tt.fields.rsaPrivateKey,
				consumerKey:      tt.fields.consumerKey,
				username:         tt.fields.username,
				authServerURL:    tt.fields.authServerURL,
				accessToken:      tt.fields.accessToken,
				accessTokenMutex: tt.fields.accessTokenMutex,
			}
			gotErr := c.newAccessToken()
			if !reflect.DeepEqual(gotErr, tt.wantErr) {
				t.Errorf("newAccessToken() = %+v, want %+v", gotErr, tt.wantErr)
			}
		})
	}
}

func TestClient_sendRequest(t *testing.T) {
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

	testServerBadResFmtBody := []byte(`this_is_in_an_un-understandable_format`)
	testServerBadResFmtStatusCode := http.StatusInternalServerError
	var aux APIErrs
	testServerBadResFmtErr := json.Unmarshal(testServerBadResFmtBody, &aux)
	testServerBadResFmt := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(testServerBadResFmtStatusCode)
		rw.Write(testServerBadResFmtBody)
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
		err        error
	}
	tests := []struct {
		name string
		args args
		want expected
	}{
		{
			name: "NewRequestWithNilBody/Error",
			args: args{
				ctx: nil,
			},
			want: expected{
				statusCode: -1,
				err:        errors.New("net/http: nil Context"),
			},
		},
		{
			name: "NewRequestWithBody/Error",
			args: args{
				ctx:         nil,
				requestBody: []byte("test"),
			},
			want: expected{
				statusCode: -1,
				err:        errors.New("net/http: nil Context"),
			},
		},
		{
			name: "UnexpectedStatusCode",
			args: args{
				ctx:     context.Background(),
				method:  http.MethodGet,
				url:     testServerTeapot.URL,
				headers: http.Header{"headerName": []string{"value1", "value2"}},
			},
			want: expected{
				statusCode: testServerTeapotStatusCode,
				resBody:    testServerTeapotResBody,
				err:        fmt.Errorf("unexpected HTTP status code: %d", http.StatusTeapot),
			},
		},
		{
			name: "NilBodySuccess",
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
		},
		{
			name: "ErroneousStatusCode/UnexpectedResponseFormat",
			args: args{
				ctx:    context.Background(),
				method: http.MethodGet,
				url:    testServerBadResFmt.URL,
			},
			want: expected{
				statusCode: testServerBadResFmtStatusCode,
				err:        testServerBadResFmtErr,
			},
		},
		{
			name: "ErroneousStatusCode",
			args: args{
				ctx:    context.Background(),
				method: http.MethodGet,
				url:    testServerErr.URL,
			},
			want: expected{
				statusCode: testServerErrStatusCode,
				resBody:    testServerErrBody,
				err:        &testServerErrSfErr,
			},
		},
		{
			name: "Success",
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
		},
	}
	for _, tt := range tests {
		c := &jwtBearer{
			client:           http.Client{},
			rsaPrivateKey:    testRSAPrivateKey,
			accessTokenMutex: &sync.RWMutex{},
		}

		t.Run(tt.name, func(t *testing.T) {
			statusCode, resBody, err := c.sendRequest(tt.args.ctx, tt.args.method, tt.args.url, tt.args.headers, tt.args.requestBody)
			switch {
			case !reflect.DeepEqual(statusCode, tt.want.statusCode):
				t.Errorf("newAccessToken() statusCode = %+v, want %+v", statusCode, tt.want.statusCode)
			case !reflect.DeepEqual(resBody, tt.want.resBody):
				t.Errorf("newAccessToken() responseBody = %+v, want %+v", resBody, tt.want.resBody)
			case !reflect.DeepEqual(err, tt.want.err):
				t.Errorf("newAccessToken() err = %+v, want %+v", err, tt.want.err)
			}
		})
	}
}

func TestClient_SendRequest(t *testing.T) {
	testAccessToken := "token_williams"

	testServerBadResFmtStatusCode := http.StatusInternalServerError
	testServerBadResFmtBody := []byte(`this_is_in_an_un-understandable_format`)
	var aux APIErrs
	testServerBadResFmtErr := json.Unmarshal(testServerBadResFmtBody, &aux)
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

	type args struct {
		ctx         context.Context
		method      string
		relURL      string
		headers     http.Header
		requestBody []byte
	}
	type fields struct {
		instanceURL     string
		consumerKey     string
		username        string
		authServerURL   string
		accessToken     string
		tokenExpiration time.Time
	}
	type expected struct {
		statusCode int
		resBody    []byte
		err        error
	}
	tests := []struct {
		name   string
		args   args
		fields fields
		want   expected
	}{
		{
			name: "sendRequest/Error",
			fields: fields{
				instanceURL:     testServerBadResFmt.URL,
				tokenExpiration: time.Now().Add(1 * time.Hour),
			},
			want: expected{
				statusCode: testServerBadResFmtStatusCode,
				err:        testServerBadResFmtErr,
			},
		},
		{
			name: "ExpiredToken/NewTokenError",
			fields: fields{
				instanceURL:     testServerNewTokenErr.URL,
				tokenExpiration: time.Now().Add(-1 * time.Hour),
			},
			args: args{
				method: http.MethodGet,
				relURL: "/something",
			},
			want: expected{
				statusCode: -1,
				err:        &testServerNewTokenErrErr,
			},
		},
		{
			name: "Unauthorized/NewTokenSuccess/Request/Error",
			fields: fields{
				instanceURL:     testServerGetNewToken.URL,
				tokenExpiration: time.Now().Add(1 * time.Hour),
			},
			args: args{
				method: http.MethodGet,
				relURL: "/something",
			},
			want: expected{
				statusCode: testServerGetNewTokenStatusCode,
				resBody:    testServerGetNewTokenBody2,
				err:        &testServerGetNewTokenErr,
			},
		},
		{
			name: "Unauthorized/NewTokenError",
			fields: fields{
				instanceURL:     testServerNewTokenErr.URL,
				tokenExpiration: time.Now().Add(1 * time.Hour),
			},
			args: args{
				method: http.MethodGet,
				relURL: "/something",
			},
			want: expected{
				statusCode: -1,
				err:        &testServerNewTokenErrErr,
			},
		},
		{
			name: "Unauthorized/NewToken/Success",
			fields: fields{
				instanceURL:     testServerUnauthorizedNewTokenSuccess.URL,
				tokenExpiration: time.Now().Add(1 * time.Hour),
			},
			args: args{
				method: http.MethodGet,
				relURL: "/something",
			},
			want: expected{
				statusCode: testServerUnauthorizedNewTokenSuccessStatusCode,
				resBody:    testServerUnauthorizedNewTokenSuccessBody,
			},
		},
	}
	for _, tt := range tests {
		c := &jwtBearer{
			client:           http.Client{},
			instanceURL:      tt.fields.instanceURL,
			rsaPrivateKey:    testRSAPrivateKey,
			consumerKey:      tt.fields.consumerKey,
			username:         tt.fields.username,
			authServerURL:    tt.fields.authServerURL,
			accessToken:      tt.fields.accessToken,
			tokenExpiration:  tt.fields.tokenExpiration,
			accessTokenMutex: &sync.RWMutex{},
		}
		t.Run(tt.name, func(t *testing.T) {
			statusCode, resBody, err := c.SendRequest(context.Background(), tt.args.method, tt.args.relURL, tt.args.headers, tt.args.requestBody)
			switch {
			case !reflect.DeepEqual(statusCode, tt.want.statusCode):
				t.Errorf("SendRequest() statusCode = %+v, want %+v", statusCode, tt.want.statusCode)
			case !reflect.DeepEqual(resBody, tt.want.resBody):
				t.Errorf("SendRequest() responseBody = %+v, want %+v", resBody, tt.want.resBody)
			case !reflect.DeepEqual(err, tt.want.err):
				t.Errorf("SendRequest() err = %+v, want %+v", err, tt.want.err)
			}
		})
	}
}
