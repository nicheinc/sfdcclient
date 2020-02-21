package sfdcclient

import (
	"context"
	"net/http"
	"sync/atomic"
)

type ClientMock struct {
	SendRequestStub   func(ctx context.Context, method string, relURL string, headers http.Header, requestBody []byte) (int, []byte, error)
	SendRequestCalled int32
}

var _ Client = &ClientMock{}

func (m *ClientMock) SendRequest(ctx context.Context, method string, relURL string, headers http.Header, requestBody []byte) (int, []byte, error) {
	atomic.AddInt32(&m.SendRequestCalled, 1)
	return m.SendRequestStub(ctx, method, relURL, headers, requestBody)
}
