// Package capture provides an HTTP capture proxy. All integrated tools
// (dalfox, nikto, sqlmap, nuclei) route through it. Every request/response
// pair is stored with a unique ID. Findings reference the capture ID to
// show full raw traffic. Optionally chains to an upstream proxy (Burp).
package capture

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

// Entry is one captured request/response pair.
type Entry struct {
	ID        int64     `json:"id"`
	Method    string    `json:"method"`
	URL       string    `json:"url"`
	Host      string    `json:"host"`
	Request   string    `json:"request"`
	Response  string    `json:"response"`
	Status    int       `json:"status"`
	Length    int       `json:"length"`
	Duration  int64     `json:"duration_ms"`
	Timestamp time.Time `json:"timestamp"`
}

// Store holds all captured traffic.
type Store struct {
	mu      sync.RWMutex
	entries map[int64]*Entry
	counter atomic.Int64
}

func NewStore() *Store {
	return &Store{entries: make(map[int64]*Entry)}
}

func (s *Store) Add(e *Entry) {
	s.mu.Lock()
	s.entries[e.ID] = e
	s.mu.Unlock()
}

func (s *Store) Get(id int64) *Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.entries[id]
}

func (s *Store) All() []*Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Entry, 0, len(s.entries))
	for _, e := range s.entries {
		out = append(out, e)
	}
	return out
}

func (s *Store) NextID() int64 {
	return s.counter.Add(1)
}

// Proxy is an HTTP/HTTPS capture proxy.
type Proxy struct {
	Store    *Store
	Upstream string // upstream proxy URL (e.g. http://127.0.0.1:8080 for Burp)
	ln       net.Listener
	addr     string
}

// New creates a capture proxy. upstream="" means direct connection.
func New(upstream string) *Proxy {
	return &Proxy{
		Store:    NewStore(),
		Upstream: upstream,
	}
}

// Start listens on the given port. Returns the proxy address.
func (p *Proxy) Start(port int) (string, error) {
	if port <= 0 {
		port = 0
	}
	ln, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return "", err
	}
	p.ln = ln
	p.addr = ln.Addr().String()

	srv := &http.Server{Handler: p}
	go srv.Serve(ln)
	return p.addr, nil
}

// Addr returns the proxy listen address.
func (p *Proxy) Addr() string { return p.addr }

// ProxyURL returns the proxy URL for HTTP_PROXY/HTTPS_PROXY env vars.
func (p *Proxy) ProxyURL() string {
	return "http://" + p.addr
}

// ServeHTTP handles proxy requests (both CONNECT for HTTPS and regular HTTP).
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.handleHTTP(w, r)
}

func (p *Proxy) transport() *http.Transport {
	t := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		// Disable keep-alive to get clean per-request captures
		DisableKeepAlives: true,
	}
	if p.Upstream != "" {
		proxyURL, _ := url.Parse(p.Upstream)
		if proxyURL != nil {
			t.Proxy = http.ProxyURL(proxyURL)
		}
	}
	return t
}

func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	id := p.Store.NextID()
	start := time.Now()

	// Build raw request string
	var reqBuf bytes.Buffer
	fmt.Fprintf(&reqBuf, "%s %s HTTP/1.1\r\n", r.Method, r.URL.String())
	fmt.Fprintf(&reqBuf, "Host: %s\r\n", r.Host)
	for k, vals := range r.Header {
		for _, v := range vals {
			fmt.Fprintf(&reqBuf, "%s: %s\r\n", k, v)
		}
	}
	reqBuf.WriteString("\r\n")
	if r.Body != nil {
		bodyBytes, _ := io.ReadAll(io.LimitReader(r.Body, 64*1024))
		reqBuf.Write(bodyBytes)
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	// Forward request
	resp, err := p.transport().RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Read response body
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))

	// Build raw response string
	var resBuf bytes.Buffer
	fmt.Fprintf(&resBuf, "HTTP/1.1 %s\r\n", resp.Status)
	for k, vals := range resp.Header {
		for _, v := range vals {
			fmt.Fprintf(&resBuf, "%s: %s\r\n", k, v)
		}
	}
	resBuf.WriteString("\r\n")
	resBuf.Write(respBody)

	// Store the capture
	p.Store.Add(&Entry{
		ID:        id,
		Method:    r.Method,
		URL:       r.URL.String(),
		Host:      r.Host,
		Request:   reqBuf.String(),
		Response:  resBuf.String(),
		Status:    resp.StatusCode,
		Length:    len(respBody),
		Duration:  time.Since(start).Milliseconds(),
		Timestamp: start,
	})

	// Forward response to client
	for k, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	// CONNECT tunneling for HTTPS — pass through without MITM
	// (to MITM we'd need a CA cert; for now, just tunnel and capture the CONNECT)
	var targetConn net.Conn
	var err error

	if p.Upstream != "" {
		// Chain to upstream proxy
		proxyURL, _ := url.Parse(p.Upstream)
		if proxyURL != nil {
			targetConn, err = net.DialTimeout("tcp", proxyURL.Host, 10*time.Second)
			if err == nil {
				// Send CONNECT to upstream
				fmt.Fprintf(targetConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", r.Host, r.Host)
				// Read upstream response (skip it)
				buf := make([]byte, 1024)
				targetConn.SetReadDeadline(time.Now().Add(5 * time.Second))
				targetConn.Read(buf)
				targetConn.SetReadDeadline(time.Time{})
			}
		}
	}

	if targetConn == nil {
		targetConn, err = net.DialTimeout("tcp", r.Host, 10*time.Second)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		targetConn.Close()
		return
	}

	w.WriteHeader(http.StatusOK)
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		targetConn.Close()
		return
	}

	go transfer(targetConn, clientConn)
	go transfer(clientConn, targetConn)
}

func transfer(dst, src net.Conn) {
	defer dst.Close()
	defer src.Close()
	io.Copy(dst, src)
}
