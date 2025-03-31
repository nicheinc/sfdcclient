package expect

import (
	"sync/atomic"
	"testing"
)

// TMock is a mock implementation of the T
// interface.
type TMock struct {
	T            *testing.T
	HelperStub   func()
	HelperCalled int32
	ErrorfStub   func(format string, args ...any)
	ErrorfCalled int32
	FatalfStub   func(format string, args ...any)
	FatalfCalled int32
}

// Verify that *TMock implements T.
var _ T = &TMock{}

// Helper is a stub for the T.Helper
// method that records the number of times it has been called.
func (m *TMock) Helper() {
	atomic.AddInt32(&m.HelperCalled, 1)
	if m.HelperStub == nil {
		if m.T != nil {
			m.T.Error("HelperStub is nil")
		}
		panic("Helper unimplemented")
	}
	m.HelperStub()
}

// Errorf is a stub for the T.Errorf
// method that records the number of times it has been called.
func (m *TMock) Errorf(format string, args ...any) {
	atomic.AddInt32(&m.ErrorfCalled, 1)
	if m.ErrorfStub == nil {
		if m.T != nil {
			m.T.Error("ErrorfStub is nil")
		}
		panic("Errorf unimplemented")
	}
	m.ErrorfStub(format, args...)
}

// Fatalf is a stub for the T.Fatalf
// method that records the number of times it has been called.
func (m *TMock) Fatalf(format string, args ...any) {
	atomic.AddInt32(&m.FatalfCalled, 1)
	if m.FatalfStub == nil {
		if m.T != nil {
			m.T.Error("FatalfStub is nil")
		}
		panic("Fatalf unimplemented")
	}
	m.FatalfStub(format, args...)
}
