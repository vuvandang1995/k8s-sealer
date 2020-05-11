package rest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	sealer "github.com/teko-vn/k8s-sealer"
)

// Handler is a collection of all the service handlers.
type Handler struct {
	SealHandler *SealHandler
}

// ServeHTTP delegates a request to the appropriate subhandler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/seal") {
		h.SealHandler.ServeHTTP(w, r)
	} else {
		http.NotFound(w, r)
	}
}

func Error(w http.ResponseWriter, err error, code int) {
	// Log error.
	fmt.Printf("http error: %s (code=%d)", err, code)

	// Hide error from client if it is internal.
	if code == http.StatusInternalServerError {
		err = sealer.ErrInternal
	}

	// Write generic error response.
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(&errorResponse{Err: err.Error()})
}

// errorResponse is a generic response for sending a error.
type errorResponse struct {
	Err string `json:"err,omitempty"`
}

// NotFound writes an API error message to the response.
func NotFound(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte(`{}` + "\n"))
}

// encodeJSON encodes v to w in JSON format. Error() is called if encoding fails.
func encodeJSON(w http.ResponseWriter, v interface{}) {
	if err := json.NewEncoder(w).Encode(v); err != nil {
		Error(w, err, http.StatusInternalServerError)
	}
}
