package httpx

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

// chiURLParam reads a URL parameter.
//
// A thin wrapper so the handlers do not each import chi: the transport library is an
// implementation detail of this package, and a handler that reaches for it directly
// is one that cannot be tested without a router.
func chiURLParam(r *http.Request, name string) string {
	return chi.URLParam(r, name)
}
