package rest

import (
	"net"
	"net/http"
)

// DefaultAddr is the default bind address.
const DefaultAddr = ":3000"

// Server represents an HTTP server.
type Server struct {
	ln net.Listener

	// Handler to serve.
	Handler *Handler

	// Bind address to open.
	Addr string
}

// NewServer returns a new instance of Server.
func NewServer() *Server {
	return &Server{
		Addr: DefaultAddr,
	}

}

// Open opens a socket and serves the HTTP server.
func (s *Server) Open() error {
	// Open socket.
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err

	}
	s.ln = ln

	// Start HTTP server.
	go func() { http.Serve(s.ln, accessControl(s.Handler)) }()

	return nil

}

// Close closes the socket.
func (s *Server) Close() error {
	if s.ln != nil {
		s.ln.Close()

	}
	return nil

}

// Port returns the port that the server is open on. Only valid after open.
func (s *Server) Port() int {
	return s.ln.Addr().(*net.TCPAddr).Port

}

func accessControl(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Method", "POST, GET, PUT, PATCH")

		if r.Method == "OPTIONS" {
			return

		}

		h.ServeHTTP(w, r)

	})

}
