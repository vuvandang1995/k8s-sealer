package rest

import (
	"encoding/json"
	"net/http"

	"github.com/julienschmidt/httprouter"
	sealer "github.com/teko-vn/k8s-sealer"
)

// SealHandler represents an HTTP API handler
type SealHandler struct {
	*httprouter.Router

	SealService sealer.SealService
}

// NewSealHandler returns an instance of SealHandler
func NewSealHandler() *SealHandler {
	h := &SealHandler{
		Router: httprouter.New(),
	}
	h.POST("/api/seal/opaque", h.handleSealOpaque)
	h.POST("/api/seal/dockerconfigjson", h.handleSealDockerconfigjson)
	h.POST("/api/seal/tls", h.handleSealTLS)
	return h
}

func (h *SealHandler) handleSealOpaque(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var req sealOpaqueRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, err, http.StatusForbidden)
		return
	}
	var res sealResponse
	err := h.SealService.SealOpaque(&res, req.Cluster, req.Name, req.Namespace, req.Data)
	if err != nil {
		Error(w, err, http.StatusInternalServerError)
		return
	}

	encodeJSON(w, res)
}

func (h *SealHandler) handleSealDockerconfigjson(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var req sealDockerconfigjsonRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, err, http.StatusForbidden)
		return
	}
	var res sealResponse
	err := h.SealService.SealDockerconfigjson(&res, req.Cluster, req.Name, req.Namespace, req.Username, req.Password)
	if err != nil {
		Error(w, err, http.StatusInternalServerError)
		return
	}

	encodeJSON(w, res)
}

func (h *SealHandler) handleSealTLS(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var req sealTLSRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, err, http.StatusForbidden)
		return
	}

	var res sealResponse
	err := h.SealService.SealTLS(&res, req.Cluster, req.Namespace, req.Domain)
	if err != nil {
		Error(w, err, http.StatusInternalServerError)
		return
	}
	encodeJSON(w, res)
}

type sealOpaqueRequest struct {
	Cluster   string            `json:"cluster"`
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Data      map[string][]byte `json:"data"`
}

type sealDockerconfigjsonRequest struct {
	Cluster   string `json:"cluster"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Username  string `json:"username"`
	Password  string `json:"password"`
}

type sealTLSRequest struct {
	Cluster   string `json:"cluster"`
	Namespace string `json:"namespace"`
	Domain    string `json:"domain"`
}

type sealResponse struct {
	SealedSecret []byte `json:"sealedSecret,omitempty"`
	Err          string `json:"err,omitempty"`
}

func (r *sealResponse) Write(p []byte) (n int, err error) {
	r.SealedSecret = append(r.SealedSecret, p...)
	return len(p), nil
}
