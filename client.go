package sfdcclient

import (
	"context"
	"net/http"
)

type Client interface {
	SendRequest(ctx context.Context, method, relURL string, headers http.Header, requestBody []byte) (int, []byte, error)
}
