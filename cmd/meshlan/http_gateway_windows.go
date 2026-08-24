//go:build windows

package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

type httpGatewayRuntime struct {
	listener       net.Listener
	server         *http.Server
	address        string
	lastError      string
	httpsListener  net.Listener
	httpsServer    *http.Server
	httpsAddress   string
	httpsCertID    [32]byte
	httpsLastError string
	caFingerprint  string
	certificateEnd time.Time
	trustInstalled bool
}

type HTTPGatewayStatus struct {
	Active         bool      `json:"active"`
	Address        string    `json:"address,omitempty"`
	LastError      string    `json:"lastError,omitempty"`
	HTTPSActive    bool      `json:"httpsActive"`
	HTTPSAddress   string    `json:"httpsAddress,omitempty"`
	HTTPSLastError string    `json:"httpsLastError,omitempty"`
	CAFingerprint  string    `json:"caFingerprint,omitempty"`
	CertificateEnd time.Time `json:"certificateEnd,omitempty"`
	TrustInstalled bool      `json:"trustInstalled"`
}

type countingReadCloser struct {
	httpReadCloser
	bytes uint64
}

type httpReadCloser interface {
	Read([]byte) (int, error)
	Close() error
}

func (c *countingReadCloser) Read(buffer []byte) (int, error) {
	count, err := c.httpReadCloser.Read(buffer)
	c.bytes += uint64(count)
	return count, err
}

type countingResponseWriter struct {
	http.ResponseWriter
	bytes uint64
}

func (w *countingResponseWriter) Write(data []byte) (int, error) {
	count, err := w.ResponseWriter.Write(data)
	w.bytes += uint64(count)
	return count, err
}

func (w *countingResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *countingResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("HTTP gateway does not support hijacking")
	}
	return hijacker.Hijack()
}

func (w *countingResponseWriter) Push(target string, options *http.PushOptions) error {
	if pusher, ok := w.ResponseWriter.(http.Pusher); ok {
		return pusher.Push(target, options)
	}
	return http.ErrNotSupported
}

func bareRequestHost(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	return strings.Trim(value, "[]")
}

func (a *clientApp) httpGatewayHandler(w http.ResponseWriter, r *http.Request) {
	host := bareRequestHost(r.Host)
	a.stateMu.Lock()
	state, err := a.load()
	if err == nil {
		applyMeshDNSPreferenceDefaults(&state)
	}
	var mapping *LocalServiceMapping
	if err == nil {
		for index := range state.ServiceMappings {
			candidate := &state.ServiceMappings[index]
			if !candidate.PortlessHTTP || normalizeMappingProtocol(candidate.Protocol) != "tcp" {
				continue
			}
			if host == serviceDNSName(candidate.DNSPrefix, state.DNSPrefix) {
				copy := *candidate
				mapping = &copy
				break
			}
		}
	}
	a.stateMu.Unlock()
	if err != nil {
		http.Error(w, "MeshLAN state unavailable", http.StatusServiceUnavailable)
		return
	}
	if mapping == nil {
		http.Error(w, "MeshLAN service domain not found", http.StatusNotFound)
		return
	}
	if mapping.Paused {
		http.Error(w, "MeshLAN service is paused", http.StatusServiceUnavailable)
		return
	}
	if r.TLS == nil && a.httpsGatewayActive() {
		target := "https://" + host + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusPermanentRedirect)
		return
	}
	remoteHost, _, _ := net.SplitHostPort(r.RemoteAddr)
	allowed, userName := a.remoteAllowed(mapping.ID, state.Name, mapping.ApprovalRequired, remoteHost)
	if !allowed {
		a.updateConnection(mapping.ID, mapping.ServiceName, userName, remoteHost, "http", false, 0, 0, 0)
		http.Error(w, "MeshLAN service access requires approval", http.StatusForbidden)
		return
	}
	target, _ := url.Parse("http://" + net.JoinHostPort(mapping.LocalHost, fmt.Sprintf("%d", mapping.LocalPort)))
	originalHost := r.Host
	requestBody := &countingReadCloser{httpReadCloser: r.Body}
	r.Body = requestBody
	responseWriter := &countingResponseWriter{ResponseWriter: w}
	proxy := httputil.NewSingleHostReverseProxy(target)
	defaultDirector := proxy.Director
	proxy.Director = func(request *http.Request) {
		defaultDirector(request)
		request.Header.Set("X-Forwarded-Host", originalHost)
		request.Header.Set("X-MeshLAN-Service-Domain", host)
		request.Host = target.Host
	}
	proxy.FlushInterval = -1
	proxy.ErrorHandler = func(writer http.ResponseWriter, _ *http.Request, proxyErr error) {
		http.Error(writer, "MeshLAN local service unavailable: "+proxyErr.Error(), http.StatusBadGateway)
	}
	a.updateConnection(mapping.ID, mapping.ServiceName, userName, remoteHost, "http", true, 1, 0, 0)
	defer func() {
		a.updateConnection(mapping.ID, mapping.ServiceName, userName, remoteHost, "http", true, -1, requestBody.bytes, responseWriter.bytes)
	}()
	proxy.ServeHTTP(responseWriter, r)
}

func (a *clientApp) httpsGatewayActive() bool {
	a.gatewayMu.Lock()
	defer a.gatewayMu.Unlock()
	return a.httpGateway != nil && a.httpGateway.httpsListener != nil
}

func (a *clientApp) ensureHTTPGateway(meshIP string, certificate *tls.Certificate, identity meshHTTPSIdentity) error {
	address := net.JoinHostPort(meshIP, "80")
	httpsAddress := net.JoinHostPort(meshIP, "443")
	a.gatewayMu.Lock()
	defer a.gatewayMu.Unlock()
	if a.httpGateway == nil {
		a.httpGateway = &httpGatewayRuntime{}
	}
	if a.httpGateway.listener == nil || a.httpGateway.address != address {
		if a.httpGateway.server != nil {
			_ = a.httpGateway.server.Close()
		}
		listener, err := net.Listen("tcp", address)
		if err != nil {
			a.httpGateway.address, a.httpGateway.lastError = address, err.Error()
			return fmt.Errorf("无法监听HTTP无端口网关 %s: %w", address, err)
		}
		server := &http.Server{Handler: http.HandlerFunc(a.httpGatewayHandler), ReadHeaderTimeout: 8 * time.Second, IdleTimeout: 90 * time.Second}
		a.httpGateway.listener, a.httpGateway.server, a.httpGateway.address, a.httpGateway.lastError = listener, server, address, ""
		go a.serveGateway(server, listener, false)
	}
	if certificate == nil {
		return nil
	}
	certID := sha256.Sum256(certificate.Certificate[0])
	if a.httpGateway.httpsListener != nil && a.httpGateway.httpsAddress == httpsAddress && a.httpGateway.httpsCertID == certID {
		return nil
	}
	if a.httpGateway.httpsServer != nil {
		_ = a.httpGateway.httpsServer.Close()
	}
	listener, err := tls.Listen("tcp", httpsAddress, &tls.Config{Certificates: []tls.Certificate{*certificate}, MinVersion: tls.VersionTLS13})
	if err != nil {
		a.httpGateway.httpsAddress, a.httpGateway.httpsLastError = httpsAddress, err.Error()
		return fmt.Errorf("无法监听HTTPS无端口网关 %s: %w", httpsAddress, err)
	}
	server := &http.Server{Handler: http.HandlerFunc(a.httpGatewayHandler), ReadHeaderTimeout: 8 * time.Second, IdleTimeout: 90 * time.Second}
	a.httpGateway.httpsListener, a.httpGateway.httpsServer, a.httpGateway.httpsAddress = listener, server, httpsAddress
	a.httpGateway.httpsCertID, a.httpGateway.httpsLastError = certID, ""
	a.httpGateway.caFingerprint, a.httpGateway.certificateEnd, a.httpGateway.trustInstalled = identity.CAFingerprint, identity.NotAfter, identity.TrustInstalled
	go a.serveGateway(server, listener, true)
	return nil
}

func (a *clientApp) serveGateway(server *http.Server, listener net.Listener, https bool) {
	if serveErr := server.Serve(listener); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		a.gatewayMu.Lock()
		defer a.gatewayMu.Unlock()
		if a.httpGateway == nil {
			return
		}
		if https && a.httpGateway.httpsServer == server {
			a.httpGateway.httpsLastError = serveErr.Error()
			a.httpGateway.httpsListener = nil
		} else if !https && a.httpGateway.server == server {
			a.httpGateway.lastError = serveErr.Error()
			a.httpGateway.listener = nil
		}
	}
}

func (a *clientApp) closeHTTPGateway() {
	a.gatewayMu.Lock()
	defer a.gatewayMu.Unlock()
	if a.httpGateway == nil {
		return
	}
	if a.httpGateway.server != nil {
		_ = a.httpGateway.server.Close()
	}
	if a.httpGateway.httpsServer != nil {
		_ = a.httpGateway.httpsServer.Close()
	}
	a.httpGateway = nil
}

func (a *clientApp) syncHTTPGateway() error {
	a.stateMu.Lock()
	state, err := a.load()
	a.stateMu.Unlock()
	if err != nil {
		return err
	}
	required := false
	for _, mapping := range state.ServiceMappings {
		if mapping.PortlessHTTP && normalizeMappingProtocol(mapping.Protocol) == "tcp" {
			required = true
			break
		}
	}
	if !required {
		a.closeHTTPGateway()
		return nil
	}
	meshIP, _, err := meshAddressDetails(state)
	if err != nil {
		return err
	}
	certificate, identity, certErr := a.ensureMeshHTTPSIdentity(state)
	if certErr != nil {
		if err := a.ensureHTTPGateway(meshIP, nil, meshHTTPSIdentity{}); err != nil {
			return err
		}
		a.gatewayMu.Lock()
		if a.httpGateway != nil {
			a.httpGateway.httpsLastError = certErr.Error()
		}
		a.gatewayMu.Unlock()
		return certErr
	}
	return a.ensureHTTPGateway(meshIP, &certificate, identity)
}

func (a *clientApp) httpGatewayStatus() HTTPGatewayStatus {
	a.gatewayMu.Lock()
	defer a.gatewayMu.Unlock()
	if a.httpGateway == nil {
		return HTTPGatewayStatus{}
	}
	return HTTPGatewayStatus{
		Active: a.httpGateway.listener != nil, Address: a.httpGateway.address, LastError: a.httpGateway.lastError,
		HTTPSActive: a.httpGateway.httpsListener != nil, HTTPSAddress: a.httpGateway.httpsAddress, HTTPSLastError: a.httpGateway.httpsLastError,
		CAFingerprint: a.httpGateway.caFingerprint, CertificateEnd: a.httpGateway.certificateEnd, TrustInstalled: a.httpGateway.trustInstalled,
	}
}
