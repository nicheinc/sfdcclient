package expect

import (
	"reflect"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/exp/constraints"
)

// Equal asserts that actual = expected according to the semantics of
// [cmp.Equal]/[cmp.Diff]. It forwards opts to the cmp library; see the
// [cmp.Option documentation] for details. For error-checking, an
// expect.ErrorCheck is usually preferred.
//
// [cmp.Equal]: https://pkg.go.dev/github.com/google/go-cmp/cmp#Equal
// [cmp.Diff]: https://pkg.go.dev/github.com/google/go-cmp/cmp#Diff
// [cmp.Option documentation]: https://pkg.go.dev/github.com/google/go-cmp/cmp#Option
func Equal[U any](t T, actual, expected U, opts ...cmp.Option) {
	t.Helper()
	if diff := cmp.Diff(expected, actual, opts...); diff != "" {
		t.Errorf("Unexpected value:\n%s\n", diff)
	}
}

// EqualUnordered asserts that the actual and expected slices have the same
// elements, irrespective of order. It's a convenience function for calling
// expect.Equal with [cmpopts.SortSlices], using < in the lessFunc.
//
// [cmpopts.SortSlices]: https://pkg.go.dev/github.com/google/go-cmp/cmp/cmpopts#SortSlices
func EqualUnordered[Slice ~[]Elem, Elem constraints.Ordered](t T, actual, expected Slice, opts ...cmp.Option) {
	t.Helper()
	opts = append(opts, cmpopts.SortSlices(func(a, b Elem) bool {
		return a < b
	}))
	Equal(t, actual, expected, opts...)
}

// DeepEqual asserts that actual = expected according to the semantics of
// [reflect.DeepEqual]. This function should never be used to check error types
// since it's unaware of error wrapping. For non-errors, expect.Equal is almost
// always preferred since it has more legible output. This function exists for
// the rare circumstances where expect.Equal can't easily handle the given
// types.
//
// [reflect.DeepEqual]: https://pkg.go.dev/reflect#DeepEqual
func DeepEqual[U any](t T, actual, expected U) {
	t.Helper()
	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("Expected:\n%#v\nActual:\n%#v\n", expected, actual)
	}
}
