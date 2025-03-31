package expect

// T exposes the [testing.T] methods that the expect package uses. Calls in unit
// tests to expect package functions should pass the test's *testing.T for
// parameters of this type.
//
// [testing.T]: https://pkg.go.dev/testing#T
//
//go:generate go run github.com/nicheinc/mock@main -o testing_mock.go T
type T interface {
	Helper()
	Errorf(format string, args ...any)
	Fatalf(format string, args ...any)
}
