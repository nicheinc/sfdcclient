package expect

import (
	"errors"
)

// ErrTest is an error for use in unit tests when the specific error type
// doesn't matter. It can be useful for testing handling of arbitrary errors
// from mocked dependencies.
//
// The unit test in the following example fails because each errors.New call
// produces a new, independent error value. Changing errors.New("test error") to
// expect.ErrTest in both places allows it to pass.
//
//	func FunctionUnderTest(dependency func() error) error {
//	    return dependency()
//	}
//
//	func TestFunctionUnderTest(t *testing.T) {
//	    dependencyMock := func() error {
//	        return errors.New("test error")
//	    }
//	    expectedErr := errors.New("test error")
//	    actualErr := FunctionUnderTest(dependencyMock)
//	    if !errors.Is(actualErr, expectedErr) {
//	        t.Errorf("Unexpected error")
//	    }
//	}
var ErrTest = errors.New("test error")

// ErrorCheck is a type of [test helper function] for asserting that an error
// has an expected value. Different unit tests may call for different degrees of
// specificity when evaluating whether an error is expected, such as:
//   - Is the error nil or non-nil?
//   - Does the error contain another error?
//   - Does the error contain a list of errors?
//   - Is the error convertible to a certain type?
//
// This function provides a uniform type over these checks so that they can be
// mixed within a single table-driven test function. The other functions in this
// file are or return a function conforming to the ErrorCheck signature.
//
//	testCases := []struct{
//	    name       string
//	    // ...
//	    errorCheck expect.ErrorCheck
//	}{
//	    {
//	        name:       "CausesUnexpectedEOF",
//	        // ...
//	        errorCheck: expect.ErrorIs(io.ErrUnexpectedEOF ),
//	    }
//	    {
//	        name:       "CausesSyntaxError",
//	        // ...
//	        errorCheck: expect.ErrorAs[*json.SyntaxError](),
//	    }
//	}
//	for _, testCase := range testCases {
//	    t.Run(testCase.name, func(t *testing.T) {
//	        err := FunctionUnderTest(/* ... */)
//	        testCase.errorCheck(t, err)
//	    })
//	}
//
// [test helper function]: https://pkg.go.dev/testing#T.Helper
type ErrorCheck func(T, error)

// ErrorNil is an ErrorCheck that an error is nil.
func ErrorNil(t T, err error) {
	t.Helper()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}

// ErrorNonNil is an ErrorCheck that an error is non-nil.
func ErrorNonNil(t T, err error) {
	t.Helper()
	if err == nil {
		t.Errorf("Unexpected nil error")
	}
}

// ErrorIs returns an ErrorCheck that an error is the given error, as defined by
// [errors.Is].
//
// [errors.Is]: https://pkg.go.dev/errors#Is
func ErrorIs(expected error) ErrorCheck {
	return func(t T, err error) {
		t.Helper()
		if !errors.Is(err, expected) {
			t.Errorf("Expected error:\n%v\nActual error:\n%v\n", expected, err)
		}
	}
}

// ErrorAs returns an ErrorCheck that an error can be converted to the Target
// error type using [errors.As].
//
// [errors.As]: https://pkg.go.dev/errors#As
func ErrorAs[Target error]() ErrorCheck {
	return func(t T, err error) {
		t.Helper()
		var target Target
		if !errors.As(err, &target) {
			t.Errorf("Expected error type: %T\nActual error type:\n%T", target, err)
		}
	}
}

// ErrorIsAll returns an ErrorCheck that an error (1) is all of the given
// expected errors as defined by [errors.Is] and (2) is nil only if expected is
// empty. It does not ensure that expected is exhaustive; i.e. there could be an
// error E for which errors.Is(err, E) returns true that is not included in
// expected, despite ErrorIsAll passing.
//
// This check is useful for testing code that uses [errors.Join] to return
// multiple errors.
//
// [errors.Is]: https://pkg.go.dev/errors#Is
// [errors.Join]: https://pkg.go.dev/errors#Join
func ErrorIsAll(expected ...error) ErrorCheck {
	return func(t T, err error) {
		t.Helper()
		if err != nil && len(expected) == 0 {
			t.Errorf("Unexpected error:\n%s\n", err)
		}
		for _, expectedErr := range expected {
			if !errors.Is(err, expectedErr) {
				t.Errorf("Actual error...\n%s\n...is not expected error:\n%s\n", err, expectedErr)
			}
		}
	}
}

// Must can be used on a (value, error) pair to either get the value or
// immediately fail the test if the error is non-nil. The T parameter is
// curried, rather than passed as a third argument, so that (value, error)
// function return values can be passed to Must directly, without assigning them
// to intermediate variables.
//
// See also Must0, Must2, and Must3 for working with functions of other coarity.
//
//	bytes := expect.Must(io.ReadAll(reader))(t)
func Must[V any](value V, err error) func(T) V {
	return func(t T) V {
		t.Helper()
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		return value
	}
}

// Must0 is similar to Must but for functions returning just an error, without a
// value.
func Must0(err error) func(T) {
	return func(t T) {
		t.Helper()
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
	}
}

// Must2 is similar to Must but for functions returning two values and an error.
func Must2[V1 any, V2 any](value1 V1, value2 V2, err error) func(T) (V1, V2) {
	return func(t T) (V1, V2) {
		t.Helper()
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		return value1, value2
	}
}

// Must3 is similar to Must but for functions returning three values and an
// error.
func Must3[V1 any, V2 any, V3 any](value1 V1, value2 V2, value3 V3, err error) func(T) (V1, V2, V3) {
	return func(t T) (V1, V2, V3) {
		t.Helper()
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		return value1, value2, value3
	}
}
