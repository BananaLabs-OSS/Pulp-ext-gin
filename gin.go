// Package ginext is Pulp's Gin-based HTTP transport extension. It registers
// four capabilities covering inbound HTTP, outbound fetch, WebSocket, and SSE.
//
// All four capabilities share a single Gin engine. The engine is created by
// transport.http.inbound's Setup and the underlying server is stopped by its
// Teardown. WebSocket and SSE routes are served through the same listener —
// dedicated Gin handlers delegate based on path registration.
//
// Environment variables:
//
//	HTTP_PORT  — listen port (default 8080)
//	HTTP_CERT  — path to TLS certificate PEM (optional)
//	HTTP_KEY   — path to TLS private key PEM (optional)
package ginext

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/BananaLabs-OSS/Pulp/abi"
	"github.com/BananaLabs-OSS/Pulp/ext"
	"github.com/BananaLabs-OSS/Pulp/ssrfguard"
	"github.com/coder/websocket"
	"github.com/gin-gonic/gin"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/vmihailenco/msgpack/v5"
)

// ---------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------

const (
	// Long enough for admin operations that synchronously orchestrate
	// container provisioning (sidecar resolve + bananagine create +
	// startup wait can take ~60s in worst case).
	defaultRequestTimeout = 120 * time.Second
	defaultFetchTimeout   = 30 * time.Second
	sseKeepalive          = 15 * time.Second
)

// ---------------------------------------------------------------------
// Module-level shared state
// ---------------------------------------------------------------------

var (
	// The legacy handles preserve the original single-application ABI. In
	// endpoint-reporting host mode every application instance instead receives
	// an isolated ginServer (and its WebSocket/SSE state) below.
	server      *ginServer
	httpFetcher *fetcher
	ws          *wsServer
	sse         *sseServer

	lifecycleMu sync.Mutex

	scopedGinMu      sync.Mutex
	scopedGinServers = map[applicationInstanceKey]*scopedGinServer{}
	cellApplications = map[string]applicationInstanceKey{}
	endpointReporter ext.EndpointReporter
	endpointLogger   *slog.Logger

	fetchersMu   sync.Mutex
	cellFetchers = map[string]*fetcher{}
)

// applicationInstanceKey deliberately excludes cell identity: one app owns
// one private public listener, while many cells register routes on it.
type applicationInstanceKey struct {
	applicationID string
	instanceID    string
}

type scopedGinServer struct {
	server   *ginServer
	endpoint ext.Endpoint
	reporter ext.EndpointReporter
}

func applicationKey(scope ext.Scope) applicationInstanceKey {
	return applicationInstanceKey{applicationID: scope.ApplicationID(), instanceID: scope.ApplicationInstanceID()}
}

func scopedEndpointMode() bool {
	scopedGinMu.Lock()
	defer scopedGinMu.Unlock()
	return endpointReporter != nil
}

// ---------------------------------------------------------------------
// init — register all four capabilities
// ---------------------------------------------------------------------

func init() {
	ext.Register(ext.Capability{
		Name:          "transport.http.inbound",
		Provider:      "github.com/BananaLabs-OSS/Pulp-ext-gin",
		Register:      httpInboundRegister,
		Stub:          httpInboundStub,
		Setup:         httpInboundSetup,
		Teardown:      httpInboundTeardown,
		TeardownScope: httpInboundTeardownScope,
		TeardownCell:  httpInboundTeardownCell,
		Poll:          httpInboundPoll,
		Finalize:      httpInboundFinalize,
	})

	ext.Register(ext.Capability{
		Name:     "transport.http.outbound",
		Provider: "github.com/BananaLabs-OSS/Pulp-ext-gin",
		Register: httpOutboundRegister,
		Stub:     httpOutboundStub,
	})

	ext.Register(ext.Capability{
		Name:         "transport.ws.inbound",
		Provider:     "github.com/BananaLabs-OSS/Pulp-ext-gin",
		Register:     wsInboundRegister,
		Stub:         wsInboundStub,
		TeardownCell: transportTeardownCell,
	})

	ext.Register(ext.Capability{
		Name:         "transport.sse",
		Provider:     "github.com/BananaLabs-OSS/Pulp-ext-gin",
		Register:     sseRegister,
		Stub:         sseStub,
		TeardownCell: transportTeardownCell,
	})
}

// httpInboundTeardownCell + transportTeardownCell mark the cell
// as dead across the shared server instance. Gin's route tree is
// append-only so we can't physically remove routes; the route closures
// check `cellDead` and return 404. Any in-flight requests owned by
// the cell receive a 503 so finalize doesn't deadlock.
func httpInboundTeardownCell(_ context.Context, cellID string) error {
	return teardownGinCell(context.Background(), cellID)
}

func transportTeardownCell(_ context.Context, cellID string) error {
	return teardownGinCell(context.Background(), cellID)
}

// =====================================================================
// Gin-based HTTP server
// =====================================================================

type inflightRequest struct {
	req    abi.HTTPRequest
	respCh chan abi.HTTPResponse
	cellID string // owning cell — set when the matching route was registered
}

type ginServer struct {
	addr string
	// boundAddr is the actual address after binding. Host-mode applications
	// always bind 127.0.0.1:0, so advertising addr would be incorrect.
	boundAddr string
	logger    *slog.Logger

	engine *gin.Engine

	mu      sync.Mutex
	pending map[uint64]*inflightRequest
	nextID  atomic.Uint64

	queue    chan *inflightRequest
	srv      *http.Server
	listener net.Listener
	ws       *wsServer
	sse      *sseServer

	certPath string
	keyPath  string

	altMu      sync.Mutex
	altServers map[string]*http.Server

	// deadCells flags cells whose routes should no longer serve.
	// Gin's engine doesn't support route removal, so each route closure
	// checks cellDead() and returns 404 when true. TeardownCell
	// writes here; registerRoute clears via reviveCell() so a
	// reloaded cell with the same ID gets a clean slate.
	cellRoutesMu sync.RWMutex
	deadCells    map[string]struct{}
}

func newGinServer(addr string, logger *slog.Logger) *ginServer {
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()
	// gin.Recovery() wraps handlers so a panic inside the cell-invoked
	// dispatch loop surfaces as a 500 rather than leaving the client
	// hanging until defaultRequestTimeout. gin.New() deliberately omits
	// this; we add it back.
	engine.Use(gin.Recovery())

	// Gin's default NoRoute uses http.NotFound which injects
	// "Content-Type: text/plain; charset=utf-8" + "X-Content-Type-Options: nosniff".
	// Native Gin services (without extra NoRoute handlers) emit the
	// same headers — so this matches parity by default. But many
	// native services register no NoRoute and rely on Gin's built-in,
	// which emits the exact stdlib defaults. Override here so both
	// sides agree on "text/plain" bare (matching real-world Gin
	// services that explicitly set NoRoute) — any cell that wants
	// the stdlib shape can override by registering its own catch-all.
	engine.NoRoute(func(c *gin.Context) {
		c.Data(http.StatusNotFound, "text/plain", []byte("404 page not found"))
	})

	return &ginServer{
		addr:       addr,
		logger:     logger,
		engine:     engine,
		pending:    map[uint64]*inflightRequest{},
		queue:      make(chan *inflightRequest, 64),
		altServers: map[string]*http.Server{},
		deadCells:  map[string]struct{}{},
	}
}

// resolveGinServerForCell selects the isolated application listener in host
// endpoint mode. Legacy callers keep the process-wide server and HTTP_PORT
// behavior exactly as before.
func resolveGinServerForCell(cellID string, scope ext.Scope, requestedAddr string) *ginServer {
	if scope.IsLegacy() || !scopedEndpointMode() {
		return server
	}
	key := applicationKey(scope)
	scopedGinMu.Lock()
	defer scopedGinMu.Unlock()
	if existing := scopedGinServers[key]; existing != nil {
		// A hosted application has one public endpoint. A guest may call
		// http_listen, but cannot silently split its routes onto another host.
		if requestedAddr != "" && requestedAddr != existing.server.addr && requestedAddr != existing.server.boundAddr {
			return nil
		}
		cellApplications[cellID] = key
		return existing.server
	}
	if requestedAddr == "" {
		// The host endpoint reporter still needs a reachable listener in a
		// containerized deployment. Honor the established HTTP_PORT contract
		// for the first/public application; callers that explicitly request an
		// address retain isolated listener behavior.
		port := os.Getenv("HTTP_PORT")
		if port == "" {
			port = "8080"
		}
		requestedAddr = ":" + port
	}
	logger := endpointLogger
	if logger == nil {
		logger = slog.Default()
	}
	created := newGinServer(requestedAddr, logger)
	created.attachWebSocket(newWSServer(logger))
	created.attachSSE(newSSEServer(logger))
	if err := created.start(context.Background()); err != nil {
		logger.Error("scoped gin listener failed", "cell", cellID, "addr", requestedAddr, "err", err)
		return nil
	}
	endpoint := ext.Endpoint{Scope: scope, Capability: "transport.http.inbound", Name: "public", Address: created.boundAddr}
	if err := endpointReporter.Ready(endpoint); err != nil {
		_ = created.stop(context.Background())
		logger.Error("publish scoped gin endpoint", "cell", cellID, "addr", created.boundAddr, "err", err)
		return nil
	}
	scopedGinServers[key] = &scopedGinServer{server: created, endpoint: endpoint, reporter: endpointReporter}
	cellApplications[cellID] = key
	return created
}

func allGinServers() []*ginServer {
	scopedGinMu.Lock()
	defer scopedGinMu.Unlock()
	out := make([]*ginServer, 0, len(scopedGinServers)+1)
	if server != nil {
		out = append(out, server)
	}
	for _, owned := range scopedGinServers {
		out = append(out, owned.server)
	}
	return out
}

// existingGinServerForCell is intentionally non-creating. Outbound fetch is
// useful without an inbound listener, so binding transport.http.outbound must
// never allocate a public endpoint as a side effect.
func existingGinServerForCell(cellID string, scope ext.Scope) *ginServer {
	if scope.IsLegacy() || !scopedEndpointMode() {
		return server
	}
	scopedGinMu.Lock()
	defer scopedGinMu.Unlock()
	key, ok := cellApplications[cellID]
	if !ok {
		key = applicationKey(scope)
	}
	if owned := scopedGinServers[key]; owned != nil {
		return owned.server
	}
	return nil
}

func fetcherForCell(cellID string, logger *slog.Logger) *fetcher {
	if cellID == "" {
		return httpFetcher
	}
	fetchersMu.Lock()
	defer fetchersMu.Unlock()
	if f := cellFetchers[cellID]; f != nil {
		return f
	}
	f := newFetcher(logger)
	cellFetchers[cellID] = f
	return f
}

func dropFetcherForCell(cellID string) {
	fetchersMu.Lock()
	delete(cellFetchers, cellID)
	fetchersMu.Unlock()
}

func (s *ginServer) attachWebSocket(w *wsServer) { s.ws = w }
func (s *ginServer) attachSSE(e *sseServer)      { s.sse = e }

func (s *ginServer) enableTLS(certPath, keyPath string) error {
	if strings.TrimSpace(certPath) == "" || strings.TrimSpace(keyPath) == "" {
		return errors.New("both certPath and keyPath are required")
	}
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		return fmt.Errorf("load tls cert/key: %w", err)
	}
	s.certPath = certPath
	s.keyPath = keyPath
	s.logger.Info("http tls enabled", "cert", certPath)
	return nil
}

func (s *ginServer) registerRoute(cellID, method, pattern string) error {
	if cellID == "" {
		return errors.New("cellID is required")
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		return errors.New("method is required")
	}
	if !strings.HasPrefix(pattern, "/") {
		return fmt.Errorf("pattern %q must begin with /", pattern)
	}

	// Clear any lingering dead-mark so a re-loaded cell with the same
	// ID gets a clean slate.
	s.reviveCell(cellID)

	// Gin uses :param syntax natively — the cell's route format already
	// uses :param, so we pass the pattern straight through. If the path
	// was previously installed as an SSE route, the Gin tree will panic
	// on duplicate-route; engineHandleSafe turns that into an error we
	// swallow with a log — the SSE handler remains as the owner of the
	// path. Same deferral semantics as registerSSERoute's conflict case,
	// just the other direction.
	if err := s.engineHandleSafe(func() {
		s.engine.Handle(method, pattern, func(c *gin.Context) {
			if s.cellDead(cellID) {
				// Match bare "text/plain" shape used by NoRoute so
				// parity tests comparing a dead-cell 404 against a
				// fresh-install 404 see identical wire bytes. c.String
				// would add "; charset=utf-8" and break that.
				c.Data(http.StatusNotFound, "text/plain", []byte("404 page not found"))
				return
			}
			s.handleHTTPRequestFor(c, cellID)
		})
	}); err != nil {
		s.logger.Info("http route deferred (another route already present)", "cell", cellID, "method", method, "pattern", pattern)
		return nil
	}

	// Auto-register OPTIONS for the same pattern so CORS preflights get
	// dispatched to the cell (where global CORS middleware can handle
	// them). Native Gin services rely on this implicitly via a global
	// CORS middleware that sees every request; the host's per-(method,
	// pattern) routing model doesn't deliver OPTIONS unless it's
	// registered. Duplicate registration (multiple routes on the same
	// pattern) is harmless — engineHandleSafe swallows the panic.
	if method != "OPTIONS" {
		_ = s.engineHandleSafe(func() {
			s.engine.Handle("OPTIONS", pattern, func(c *gin.Context) {
				if s.cellDead(cellID) {
					c.Data(http.StatusNotFound, "text/plain", []byte("404 page not found"))
					return
				}
				s.handleHTTPRequestFor(c, cellID)
			})
		})
	}
	s.logger.Info("http route registered", "cell", cellID, "method", method, "pattern", pattern)
	return nil
}

func (s *ginServer) registerWSRoute(cellID, path string) error {
	if cellID == "" {
		return errors.New("cellID is required")
	}
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("ws path %q must begin with /", path)
	}
	if s.ws == nil {
		return errors.New("ws server not attached")
	}
	s.reviveCell(cellID)
	s.ws.registerRoute(path, cellID)
	if err := s.engineHandleSafe(func() {
		s.engine.GET(path, func(c *gin.Context) {
			if s.cellDead(cellID) {
				c.Data(http.StatusNotFound, "text/plain", []byte("404 page not found"))
				return
			}
			s.ws.upgrade(c.Writer, c.Request, cellID)
		})
	}); err != nil {
		return fmt.Errorf("register ws %s: %w", path, err)
	}
	s.logger.Info("ws route registered", "cell", cellID, "path", path)
	return nil
}

func (s *ginServer) registerSSERoute(cellID, path string) error {
	if cellID == "" {
		return errors.New("cellID is required")
	}
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("sse path %q must begin with /", path)
	}
	if s.sse == nil {
		return errors.New("sse server not attached")
	}
	s.reviveCell(cellID)
	// Always record the path for emit() pattern-matching; the SSE
	// server needs it in its route map so sse.Emit() knows whether a
	// given concrete path is allowed.
	s.sse.registerRoute(path)
	// Try to install a Gin handler that serves SSE directly. If the
	// cell also registered a regular GET handler at this path (e.g.
	// long-poll as a fallback for WASM where SSE step-loop is tricky),
	// Gin will panic on duplicate-route and engineHandleSafe captures
	// the error. In that case we log and continue — the cell's GET
	// handler will serve the path, and SSE emits with zero subscribers
	// are harmless no-ops. Registering the path in the sse map above
	// is still useful because emit() validates the target path belongs
	// to a known SSE route.
	if err := s.engineHandleSafe(func() {
		s.engine.GET(path, func(c *gin.Context) {
			if s.cellDead(cellID) {
				c.Data(http.StatusNotFound, "text/plain", []byte("404 page not found"))
				return
			}
			s.sse.handle(c.Writer, c.Request)
		})
	}); err != nil {
		s.logger.Info("sse route deferred (http route already present)", "cell", cellID, "path", path)
		return nil
	}
	s.logger.Info("sse route registered", "cell", cellID, "path", path)
	return nil
}

// engineHandleSafe runs a route registration with a recover. Gin's
// engine.Handle panics when a conflicting route is already registered
// (e.g., a cell reloaded before the old routes were scrubbed, or two
// cells race on the same path). We catch the panic and turn it into
// a plain error so the cell gets a useful return code instead of
// taking down the host.
func (s *ginServer) engineHandleSafe(fn func()) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("engine.Handle panic: %v", r)
		}
	}()
	fn()
	return nil
}

// reviveCell clears a stale dead-mark before registering new routes.
// Without this, a cell reloaded under the same cellID would have
// every new route born 404 because cellDead() would still see the
// old teardown flag.
func (s *ginServer) reviveCell(cellID string) {
	s.cellRoutesMu.Lock()
	delete(s.deadCells, cellID)
	s.cellRoutesMu.Unlock()
}

// cellDead reports whether a cell's routes have been retired via
// TeardownCell. The lookup is under RLock so the hot path stays
// cheap; writes via markCellDead hold the exclusive lock.
func (s *ginServer) cellDead(cellID string) bool {
	if cellID == "" {
		return false
	}
	s.cellRoutesMu.RLock()
	_, dead := s.deadCells[cellID]
	s.cellRoutesMu.RUnlock()
	return dead
}

// markCellDead flags a cell so all subsequent requests to its
// routes fall through to a 404. Also evicts any pending requests owned
// by that cell so finalize doesn't deadlock.
func (s *ginServer) markCellDead(cellID string) {
	if cellID == "" {
		return
	}
	s.cellRoutesMu.Lock()
	s.deadCells[cellID] = struct{}{}
	s.cellRoutesMu.Unlock()

	s.mu.Lock()
	for id, ir := range s.pending {
		if ir.cellID == cellID {
			delete(s.pending, id)
			select {
			case ir.respCh <- abi.HTTPResponse{ID: id, Status: 503, Body: []byte("cell removed")}:
			default:
			}
		}
	}
	s.mu.Unlock()
}

func (s *ginServer) handleHTTPRequestFor(c *gin.Context, cellID string) {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.String(http.StatusBadRequest, "read body: %s", err.Error())
		return
	}

	id := s.nextID.Add(1)
	headers := map[string]string{}
	for k, vs := range c.Request.Header {
		if len(vs) > 0 {
			headers[k] = vs[0]
		}
	}
	// Go's net/http strips the Host header from Request.Header and moves it
	// to Request.Host. Re-inject it so cells that call GetHeader("Host")
	// (e.g. for magic-link URL derivation) see the real value.
	if c.Request.Host != "" {
		headers["Host"] = c.Request.Host
	}
	query := map[string]string{}
	for k, vs := range c.Request.URL.Query() {
		if len(vs) > 0 {
			query[k] = vs[0]
		}
	}

	// Extract path params from Gin's context.
	params := map[string]string{}
	for _, p := range c.Params {
		params[p.Key] = p.Value
	}

	ir := &inflightRequest{
		req: abi.HTTPRequest{
			ID:         id,
			Method:     c.Request.Method,
			Path:       c.Request.URL.Path,
			Params:     params,
			Query:      query,
			Headers:    headers,
			Body:       body,
			RemoteAddr: c.Request.RemoteAddr,
		},
		respCh: make(chan abi.HTTPResponse, 1),
		cellID: cellID,
	}

	s.mu.Lock()
	s.pending[id] = ir
	s.mu.Unlock()

	select {
	case s.queue <- ir:
	default:
		s.mu.Lock()
		delete(s.pending, id)
		s.mu.Unlock()
		c.String(http.StatusServiceUnavailable, "queue full")
		return
	}

	select {
	case resp := <-ir.respCh:
		// Content-Type is sent via Header() rather than c.Data(ct,...)
		// because c.Data injects a default of "text/plain; charset=utf-8"
		// when given an empty content type — which would override the
		// cell's explicit choice (and fail parity against native Gin
		// handlers that emit bare "text/plain" on 404).
		for k, v := range resp.Headers {
			c.Header(k, v)
		}
		// Multiple Set-Cookie headers are required for multi-cookie
		// responses. Headers above is single-valued — cookies come
		// through a separate slice and each appends its own header.
		for _, cookie := range resp.Cookies {
			c.Writer.Header().Add("Set-Cookie", cookie)
		}
		status := int(resp.Status)
		if status == 0 {
			status = http.StatusOK
		}
		c.Writer.WriteHeader(status)
		_, _ = c.Writer.Write(resp.Body)
	case <-time.After(defaultRequestTimeout):
		s.mu.Lock()
		delete(s.pending, id)
		s.mu.Unlock()
		c.String(http.StatusGatewayTimeout, "cell timeout")
	}
}

func (s *ginServer) start(_ context.Context) error {
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.addr, err)
	}
	s.listener = listener
	s.boundAddr = listener.Addr().String()
	s.srv = &http.Server{
		Addr:    s.boundAddr,
		Handler: s.engine,
	}
	useTLS := s.certPath != "" && s.keyPath != ""
	go func() {
		var serveErr error
		if useTLS {
			serveErr = s.srv.ServeTLS(listener, s.certPath, s.keyPath)
		} else {
			serveErr = s.srv.Serve(listener)
		}
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			s.logger.Error("http listen failed", "err", serveErr)
		}
	}()
	s.logger.Info("gin server started", "addr", s.boundAddr, "tls", useTLS)
	return nil
}

func (s *ginServer) stop(ctx context.Context) error {
	s.altMu.Lock()
	alts := make([]*http.Server, 0, len(s.altServers))
	for _, srv := range s.altServers {
		alts = append(alts, srv)
	}
	s.altServers = map[string]*http.Server{}
	s.altMu.Unlock()
	for _, srv := range alts {
		_ = srv.Shutdown(ctx)
	}
	if s.srv == nil {
		return nil
	}
	return s.srv.Shutdown(ctx)
}

// ensureAltListener starts an additional http.Server on addr serving
// the same Gin engine if one is not already running there. Addresses
// that match the default server's addr are a no-op. Multiple cells
// calling with the same addr share the listener.
func (s *ginServer) ensureAltListener(addr string) error {
	if addr == "" {
		return errors.New("addr is required")
	}
	if addr == s.addr {
		return nil
	}
	s.altMu.Lock()
	if _, ok := s.altServers[addr]; ok {
		s.altMu.Unlock()
		return nil
	}
	srv := &http.Server{Addr: addr, Handler: s.engine}
	s.altServers[addr] = srv
	useTLS := s.certPath != "" && s.keyPath != ""
	certPath, keyPath := s.certPath, s.keyPath
	s.altMu.Unlock()
	go func() {
		var err error
		if useTLS {
			// Alt listeners share the main server's TLS cert/key so a
			// cell declaring a secondary listen address stays on the
			// same scheme as the primary. Without this the alt listener
			// silently serves plaintext on a port the cell expected to
			// be TLS — a correctness hole for admin-plane endpoints.
			err = srv.ListenAndServeTLS(certPath, keyPath)
		} else {
			err = srv.ListenAndServe()
		}
		if errors.Is(err, http.ErrServerClosed) {
			return
		}
		// Bind failed or listener died — drop the map entry so a later
		// retry actually re-binds instead of no-opping.
		s.altMu.Lock()
		if s.altServers[addr] == srv {
			delete(s.altServers, addr)
		}
		s.altMu.Unlock()
		if err != nil {
			s.logger.Error("alt listener failed", "addr", addr, "err", err)
		}
	}()
	s.logger.Info("alt listener started", "addr", addr)
	return nil
}

func (s *ginServer) popRequest() (abi.HTTPRequest, string, bool) {
	select {
	case ir := <-s.queue:
		return ir.req, ir.cellID, true
	default:
		return abi.HTTPRequest{}, "", false
	}
}

func (s *ginServer) respond(resp abi.HTTPResponse) error {
	s.mu.Lock()
	ir, ok := s.pending[resp.ID]
	if ok {
		delete(s.pending, resp.ID)
	}
	s.mu.Unlock()
	if !ok {
		return fmt.Errorf("no pending request id %d", resp.ID)
	}
	ir.respCh <- resp
	return nil
}

func (s *ginServer) finalize(id uint64) {
	s.mu.Lock()
	ir, still := s.pending[id]
	if still {
		delete(s.pending, id)
	}
	s.mu.Unlock()
	if still {
		s.logger.Warn("cell did not respond", "id", id)
		ir.respCh <- abi.HTTPResponse{
			ID:     id,
			Status: 500,
			Body:   []byte("cell did not respond"),
		}
	}
}

// =====================================================================
// SSRF egress guard
// =====================================================================
//
// Cells holding transport.http.outbound fetch USER-supplied URLs (e.g.
// Evolution forwards customer-supplied datapack / world-restore URLs).
// Without a guard a hostile or buggy cell could reach the cloud-metadata
// endpoint (169.254.169.254), localhost, RFC-1918 ranges, or other
// internal services on the VPS — classic SSRF. This is the production-
// wired fetcher (Evolution/pulp-deployment imports ext-gin, not ext-http),
// so the guard MUST live here, mirroring Pulp-ext-http's ssrfguard.EgressGuard.
//
// The guard does three things:
//  1. Scheme allowlist — only http/https (rejects file://, gopher://, …).
//  2. IP block — at DIAL time it validates the RESOLVED IP against a
//     deny-list of loopback / link-local / private / ULA / unspecified
//     ranges. Validating the resolved IP (not the hostname string)
//     defeats DNS-rebinding: even if a name resolves to a public IP at
//     check time and a private IP at connect time, the dialer sees the
//     real connect IP.
//  3. Redirect re-validation — http.Client.CheckRedirect re-runs the
//     scheme check on every hop, and the dialer re-runs the IP check for
//     each hop's connection, so a redirect to an internal target is
//     refused mid-chain.
//
// A genuinely-needed internal host can be allowlisted via the
// HTTP_FETCH_ALLOW env var (comma-separated host[:port] or CIDR entries).
// On TOP of whatever the env supplies, the guard seeds a built-in default
// allow-set of the platform's own first-party internal service HOSTNAMES
// (see defaultInternalServiceHosts). Those services live on the Docker
// bridge at RFC-1918 / loopback addresses, so a pure deny-all-private
// default would break Evolution's out-of-box calls to Bananagine and the
// minecraft-resolver. The exemption is keyed on the exact dialed HOSTNAME
// (e.g. "bananagine", "minecraft-resolver:8080"), NOT on an IP range — so
// it admits ONLY those known first-party names. A cell's user-supplied URL
// pointed at an arbitrary internal IP (169.254.169.254 metadata, a raw
// 10.x/172.16.x/192.168.x address, or any host not on this exact name list)
// is still IP-blocked. This is the platform egress posture, mirroring
// Pulp-ext-http; the default-allow merely restores the legit internal path
// without requiring a deploy-time HTTP_FETCH_ALLOW.
//
// The name-allowlist exemption is decided PER DIAL against the host the
// dialer is actually about to connect to, NOT pinned once onto the request
// context. This matters for redirects: an allowlisted host that 302s to a
// loopback / metadata / RFC-1918 target is still IP-blocked, because the
// redirect hop dials a DIFFERENT host that is re-checked against the
// allowlist on its own.

// defaultInternalServiceHosts is the built-in allow-set of the platform's
// own first-party internal service hostnames. These are the Docker service
// names Evolution dials by name on its hot paths — Bananagine (game
// orchestration host, default port 3000) and the minecraft-resolver
// (mod/version resolver sidecar, default port 8080). They resolve to
// private/loopback bridge IPs, so without this default the deny-all-private
// guard would block Evolution's out-of-box internal calls. Both the bare
// name and the canonical host:port form are listed so the per-dial
// HostAllowed match succeeds whether or not the dialed address carries the
// default port. Only these EXACT names are exempt; an arbitrary internal IP
// or metadata address supplied by a cell is NOT on this list and stays
// blocked. Operators can extend the set via HTTP_FETCH_ALLOW (merged by
// ssrfguard.NewEgressGuard) for non-default hostnames or ports.
var defaultInternalServiceHosts = []string{
	"bananagine",
	"bananagine:3000",
	"minecraft-resolver",
	"minecraft-resolver:8080",
}

// The SSRF egress guard is provided by the shared ssrfguard package.
// See github.com/BananaLabs-OSS/Pulp/ssrfguard for full documentation.
// ext-gin pre-seeds defaultInternalServiceHosts so Evolution reaches
// Bananagine/minecraft-resolver out-of-box; operators extend via HTTP_FETCH_ALLOW.

// =====================================================================
// Fetcher (outbound HTTP)
// =====================================================================

// maxFetchBodyBytes caps the response body read in fetcher.do() to prevent
// an oversized (or infinite) response from exhausting host memory. Matches
// the 50 MiB limit used by Pulp-ext-http's legacy http_fetch path (B13).
const maxFetchBodyBytes int64 = 50 * 1024 * 1024 // 50 MiB

type fetcher struct {
	client *http.Client
	guard  *ssrfguard.EgressGuard
	logger *slog.Logger
}

func newFetcher(logger *slog.Logger) *fetcher {
	guard := ssrfguard.NewEgressGuard(os.Getenv("HTTP_FETCH_ALLOW"), defaultInternalServiceHosts)

	// No Client.Timeout: per-request deadline is applied via context
	// inside do() so callers can override the 30s default for long
	// uploads (world archives, etc.) without affecting other requests.
	//
	// DialContext uses a net.Dialer whose Control hook runs AFTER DNS
	// resolution with the concrete IP about to be dialed — that is the
	// SSRF egress guard, and checking the resolved IP (not the hostname)
	// is what defeats DNS-rebinding.
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   guard.DialControl,
	}
	transport := &http.Transport{
		DialContext:           guard.DialContext(dialer.DialContext),
		MaxIdleConns:          128,
		MaxIdleConnsPerHost:   32,
		MaxConnsPerHost:       64,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	return &fetcher{
		client: &http.Client{
			Transport: transport,
			// Re-validate the scheme on every redirect hop. The IP block
			// is enforced by the dialer Control hook on each hop's
			// connection, so a redirect to an internal target is refused
			// at dial time even if this callback passes.
			CheckRedirect: func(req *http.Request, _ []*http.Request) error {
				return guard.CheckScheme(req)
			},
		},
		guard:  guard,
		logger: logger,
	}
}

func (f *fetcher) do(ctx context.Context, req abi.HTTPFetchRequest) (abi.HTTPResponse, error) {
	if strings.TrimSpace(req.URL) == "" {
		return abi.HTTPResponse{}, errors.New("url is required")
	}
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = http.MethodGet
	}

	timeout := defaultFetchTimeout
	if req.Timeout > 0 {
		timeout = time.Duration(req.Timeout)
	}
	// Detach from the caller ctx: a cell pulp_step/pulp_on_call runs under a
	// bounded call_timeout (Pulp/internal/host Cell.callContext), so a fetch
	// late in a heavy step would otherwise inherit an already-expired compute
	// budget and fail instantly with "context deadline exceeded" though the
	// network is fine. Bound it by the request timeout instead.
	reqCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var body io.Reader
	if len(req.Body) > 0 {
		body = bytes.NewReader(req.Body)
	}

	httpReq, err := http.NewRequestWithContext(reqCtx, method, req.URL, body)
	if err != nil {
		return abi.HTTPResponse{}, fmt.Errorf("build request: %w", err)
	}
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	httpReq, err = f.guard.Prepare(httpReq)
	if err != nil {
		return abi.HTTPResponse{}, err
	}

	resp, err := f.client.Do(httpReq)
	if err != nil {
		return abi.HTTPResponse{}, fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxFetchBodyBytes))
	if err != nil {
		return abi.HTTPResponse{}, fmt.Errorf("read response body: %w", err)
	}

	headers := map[string]string{}
	for k, vs := range resp.Header {
		if len(vs) > 0 {
			headers[k] = vs[0]
		}
	}

	return abi.HTTPResponse{
		Status:  uint32(resp.StatusCode),
		Headers: headers,
		Body:    respBody,
	}, nil
}

// =====================================================================
// WebSocket server
// =====================================================================

type wsConn struct {
	id     uint64
	path   string
	cellID string
	conn   *websocket.Conn
	cancel context.CancelFunc
}

// wsEvent pairs an encoded step event with the cell it belongs to
// so Poll can populate StepEvent.CellID for multi-cell fanout.
type wsEvent struct {
	cellID string
	data   []byte
}

type wsServer struct {
	logger *slog.Logger

	mu     sync.Mutex
	routes map[string]string // path → cellID
	conns  map[uint64]*wsConn
	nextID atomic.Uint64

	events chan wsEvent
}

func newWSServer(logger *slog.Logger) *wsServer {
	return &wsServer{
		logger: logger,
		routes: map[string]string{},
		conns:  map[uint64]*wsConn{},
		events: make(chan wsEvent, 256),
	}
}

func (w *wsServer) registerRoute(path, cellID string) {
	w.mu.Lock()
	w.routes[path] = cellID
	w.mu.Unlock()
}

// cellForPath resolves which cell owns the given ws path. Returns "" if
// the path was never registered — the read loop falls back to delivering
// events with empty CellID in that case (legacy single-cell behavior).
func (w *wsServer) cellForPath(path string) string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.routes[path]
}

func (w *wsServer) upgrade(rw http.ResponseWriter, r *http.Request, cellID string) {
	conn, err := websocket.Accept(rw, r, &websocket.AcceptOptions{
		InsecureSkipVerify: false,
	})
	if err != nil {
		w.logger.Error("ws accept failed", "err", err, "path", r.URL.Path)
		return
	}

	id := w.nextID.Add(1)
	ctx, cancel := context.WithCancel(context.Background())
	c := &wsConn{id: id, path: r.URL.Path, cellID: cellID, conn: conn, cancel: cancel}

	w.mu.Lock()
	w.conns[id] = c
	w.mu.Unlock()

	headers := map[string]string{}
	for k, vs := range r.Header {
		if len(vs) > 0 {
			headers[k] = vs[0]
		}
	}
	query := map[string]string{}
	for k, vs := range r.URL.Query() {
		if len(vs) > 0 {
			query[k] = vs[0]
		}
	}

	openPayload, err := abi.EncodeWSOpen(abi.WSOpen{
		ConnID:  id,
		Path:    r.URL.Path,
		Query:   query,
		Headers: headers,
	})
	if err == nil {
		w.enqueueEvent(cellID, abi.EventWSOpen, openPayload)
	}

	go w.readLoop(ctx, c)
}

func (w *wsServer) send(ctx context.Context, req abi.WSSendRequest) error {
	w.mu.Lock()
	c, ok := w.conns[req.ConnID]
	w.mu.Unlock()
	if !ok {
		return fmt.Errorf("no such conn id %d", req.ConnID)
	}
	var mt websocket.MessageType
	switch req.OpCode {
	case abi.WSOpCodeText:
		mt = websocket.MessageText
	case abi.WSOpCodeBinary:
		mt = websocket.MessageBinary
	default:
		return fmt.Errorf("unsupported opcode %d", req.OpCode)
	}
	return c.conn.Write(ctx, mt, req.Payload)
}

func (w *wsServer) close(req abi.WSCloseRequest) error {
	w.mu.Lock()
	c, ok := w.conns[req.ConnID]
	if ok {
		delete(w.conns, req.ConnID)
	}
	w.mu.Unlock()
	if !ok {
		return fmt.Errorf("no such conn id %d", req.ConnID)
	}
	code := websocket.StatusNormalClosure
	if req.Code != 0 {
		code = websocket.StatusCode(req.Code)
	}
	err := c.conn.Close(code, req.Reason)
	c.cancel()
	return err
}

func (w *wsServer) popEvent() (wsEvent, bool) {
	select {
	case ev := <-w.events:
		return ev, true
	default:
		return wsEvent{}, false
	}
}

func (w *wsServer) stop() {
	w.mu.Lock()
	conns := make([]*wsConn, 0, len(w.conns))
	for _, c := range w.conns {
		conns = append(conns, c)
	}
	w.conns = map[uint64]*wsConn{}
	w.mu.Unlock()

	for _, c := range conns {
		_ = c.conn.Close(websocket.StatusGoingAway, "host shutting down")
		c.cancel()
	}
}

func (w *wsServer) readLoop(ctx context.Context, c *wsConn) {
	defer func() {
		w.mu.Lock()
		_, ok := w.conns[c.id]
		if ok {
			delete(w.conns, c.id)
		}
		w.mu.Unlock()
		c.cancel()
	}()

	for {
		msgType, data, err := c.conn.Read(ctx)
		if err != nil {
			code := uint16(websocket.CloseStatus(err))
			reason := err.Error()
			if errors.Is(err, context.Canceled) {
				reason = "host canceled"
			}
			closePayload, encErr := abi.EncodeWSClose(abi.WSClose{
				ConnID: c.id,
				Code:   code,
				Reason: reason,
			})
			if encErr == nil {
				w.enqueueEvent(c.cellID, abi.EventWSClose, closePayload)
			}
			return
		}

		var opcode uint8
		switch msgType {
		case websocket.MessageText:
			opcode = abi.WSOpCodeText
		case websocket.MessageBinary:
			opcode = abi.WSOpCodeBinary
		default:
			continue
		}
		framePayload, err := abi.EncodeWSFrame(abi.WSFrame{
			ConnID:  c.id,
			OpCode:  opcode,
			Payload: data,
		})
		if err != nil {
			continue
		}
		w.enqueueEvent(c.cellID, abi.EventWSFrame, framePayload)
	}
}

func (w *wsServer) enqueueEvent(cellID, kind string, payload []byte) {
	data, err := abi.EncodeStepEvent(kind, payload)
	if err != nil {
		w.logger.Error("encode step event", "kind", kind, "err", err)
		return
	}
	select {
	case w.events <- wsEvent{cellID: cellID, data: data}:
	default:
		w.logger.Warn("ws event queue full — dropping event", "kind", kind)
	}
}

// =====================================================================
// SSE server
// =====================================================================

type sseSub struct {
	id      uint64
	path    string
	write   chan []byte
	done    chan struct{}
	stop    chan struct{} // closed by sseServer.stop() to unblock handle()
	flusher http.Flusher
	writer  http.ResponseWriter
}

type sseServer struct {
	logger *slog.Logger

	mu     sync.Mutex
	routes map[string]struct{}
	subs   map[string]map[uint64]*sseSub
	nextID atomic.Uint64
}

func newSSEServer(logger *slog.Logger) *sseServer {
	return &sseServer{
		logger: logger,
		routes: map[string]struct{}{},
		subs:   map[string]map[uint64]*sseSub{},
	}
}

func (s *sseServer) registerRoute(path string) {
	s.mu.Lock()
	s.routes[path] = struct{}{}
	s.mu.Unlock()
}

func (s *sseServer) handle(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	id := s.nextID.Add(1)
	sub := &sseSub{
		id:      id,
		path:    r.URL.Path,
		write:   make(chan []byte, 32),
		done:    make(chan struct{}),
		stop:    make(chan struct{}),
		flusher: flusher,
		writer:  w,
	}

	s.mu.Lock()
	if _, ok := s.subs[sub.path]; !ok {
		s.subs[sub.path] = map[uint64]*sseSub{}
	}
	s.subs[sub.path][id] = sub
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		if m, ok := s.subs[sub.path]; ok {
			delete(m, id)
		}
		s.mu.Unlock()
		close(sub.done)
	}()

	ticker := time.NewTicker(sseKeepalive)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-sub.stop:
			return
		case <-ticker.C:
			if _, err := w.Write([]byte(":ping\n\n")); err != nil {
				return
			}
			flusher.Flush()
		case payload := <-sub.write:
			if _, err := w.Write(payload); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (s *sseServer) emit(req abi.SSEEmitRequest) error {
	s.mu.Lock()
	if !s.matchRouteLocked(req.Path) {
		s.mu.Unlock()
		return fmt.Errorf("no sse route %q", req.Path)
	}
	targets := make([]*sseSub, 0, len(s.subs[req.Path]))
	for _, sub := range s.subs[req.Path] {
		targets = append(targets, sub)
	}
	s.mu.Unlock()

	payload := formatSSEFrame(req)
	for _, sub := range targets {
		select {
		case sub.write <- payload:
		default:
			s.logger.Warn("sse subscriber slow — dropping event", "path", req.Path, "sub", sub.id)
		}
	}
	return nil
}

// hasSubscribers returns the number of currently connected subscribers
// for a concrete path. The cell passes the actual request path it
// wants to emit to (not the :param pattern), so this is an exact-match
// lookup against the subs map.
func (s *sseServer) hasSubscribers(path string) uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return uint32(len(s.subs[path]))
}

// matchRouteLocked reports whether path matches any registered route
// pattern. Exact matches win; otherwise each registered pattern is
// split by "/" and segments compared — literal segments must match,
// ":param" segments match any non-empty token. Caller holds s.mu.
func (s *sseServer) matchRouteLocked(path string) bool {
	if _, ok := s.routes[path]; ok {
		return true
	}
	pathParts := strings.Split(path, "/")
	for pattern := range s.routes {
		if !strings.Contains(pattern, ":") {
			continue
		}
		patParts := strings.Split(pattern, "/")
		if len(patParts) != len(pathParts) {
			continue
		}
		ok := true
		for i, p := range patParts {
			if strings.HasPrefix(p, ":") {
				if pathParts[i] == "" {
					ok = false
					break
				}
				continue
			}
			if p != pathParts[i] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func (s *sseServer) stop() {
	s.mu.Lock()
	old := s.subs
	s.subs = map[string]map[uint64]*sseSub{}
	s.mu.Unlock()
	// Signal every active handler goroutine to return via its stop channel.
	// This unblocks http.Server.Shutdown instead of letting it wait
	// forever on open SSE connections. Using a dedicated stop channel
	// (rather than closing sub.write) avoids a data race with concurrent
	// emit() calls that may still hold a reference to the old sub list.
	for _, subs := range old {
		for _, sub := range subs {
			close(sub.stop)
		}
	}
}

func formatSSEFrame(req abi.SSEEmitRequest) []byte {
	var b strings.Builder
	if req.ID != "" {
		b.WriteString("id: ")
		b.WriteString(req.ID)
		b.WriteString("\n")
	}
	if req.Event != "" {
		b.WriteString("event: ")
		b.WriteString(req.Event)
		b.WriteString("\n")
	}
	for _, line := range strings.Split(req.Data, "\n") {
		b.WriteString("data: ")
		b.WriteString(line)
		b.WriteString("\n")
	}
	b.WriteString("\n")
	return []byte(b.String())
}

// =====================================================================
// Capability lifecycle: transport.http.inbound
// =====================================================================

func httpInboundSetup(env ext.SetupEnv) error {
	lifecycleMu.Lock()
	defer lifecycleMu.Unlock()
	logger := env.Logger
	if logger == nil {
		logger = slog.Default()
	}
	if httpFetcher == nil {
		httpFetcher = newFetcher(logger)
	}
	if ws == nil {
		ws = newWSServer(logger)
	}
	if sse == nil {
		sse = newSSEServer(logger)
	}

	// An endpoint reporter means a Pulp multi-application host owns external
	// routing. Allocate private listeners lazily per application when its first
	// route registers; do not read HTTP_PORT or create a process-global server.
	if env.Endpoints != nil {
		scopedGinMu.Lock()
		endpointReporter = env.Endpoints
		endpointLogger = logger
		scopedGinMu.Unlock()
		return nil
	}

	port := os.Getenv("HTTP_PORT")
	if port == "" {
		port = "8080"
	}
	addr := ":" + port
	server = newGinServer(addr, logger)

	server.attachWebSocket(ws)
	server.attachSSE(sse)

	certPath := os.Getenv("HTTP_CERT")
	keyPath := os.Getenv("HTTP_KEY")
	if certPath != "" && keyPath != "" {
		if err := server.enableTLS(certPath, keyPath); err != nil {
			return fmt.Errorf("enable tls: %w", err)
		}
	}

	return server.start(context.Background())
}

func httpInboundTeardown(ctx context.Context) error {
	lifecycleMu.Lock()
	defer lifecycleMu.Unlock()
	scopedGinMu.Lock()
	scoped := scopedGinServers
	scopedGinServers = map[applicationInstanceKey]*scopedGinServer{}
	cellApplications = map[string]applicationInstanceKey{}
	endpointReporter = nil
	endpointLogger = nil
	scopedGinMu.Unlock()
	for _, owned := range scoped {
		owned.reporter.Gone(owned.endpoint)
	}
	if ws != nil {
		ws.stop()
	}
	if sse != nil {
		sse.stop()
	}
	var firstErr error
	if server != nil {
		if err := server.stop(ctx); err != nil {
			firstErr = err
		}
	}
	for _, owned := range scoped {
		if err := owned.server.stop(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	server, httpFetcher, ws, sse = nil, nil, nil, nil
	fetchersMu.Lock()
	cellFetchers = map[string]*fetcher{}
	fetchersMu.Unlock()
	return firstErr
}

// httpInboundTeardownScope stops exactly one hosted application listener.
// Sibling applications retain their Gin engine, WebSocket/SSE state, outbound
// clients, and endpoint registrations.
func httpInboundTeardownScope(ctx context.Context, scope ext.Scope) error {
	key := applicationKey(scope)
	scopedGinMu.Lock()
	owned := scopedGinServers[key]
	delete(scopedGinServers, key)
	cellIDs := make([]string, 0)
	for cellID, cellKey := range cellApplications {
		if cellKey == key {
			cellIDs = append(cellIDs, cellID)
			delete(cellApplications, cellID)
		}
	}
	scopedGinMu.Unlock()
	for _, cellID := range cellIDs {
		dropFetcherForCell(cellID)
	}
	if owned == nil {
		return nil
	}
	owned.reporter.Gone(owned.endpoint)
	if owned.server.ws != nil {
		owned.server.ws.stop()
	}
	if owned.server.sse != nil {
		owned.server.sse.stop()
	}
	return owned.server.stop(ctx)
}

func teardownGinCell(ctx context.Context, cellID string) error {
	for _, current := range allGinServers() {
		current.markCellDead(cellID)
	}
	dropFetcherForCell(cellID)
	var retired *scopedGinServer
	scopedGinMu.Lock()
	if key, ok := cellApplications[cellID]; ok {
		delete(cellApplications, cellID)
		stillOwned := false
		for _, other := range cellApplications {
			if other == key {
				stillOwned = true
				break
			}
		}
		if !stillOwned {
			retired = scopedGinServers[key]
			delete(scopedGinServers, key)
		}
	}
	scopedGinMu.Unlock()
	if retired == nil {
		return nil
	}
	retired.reporter.Gone(retired.endpoint)
	if retired.server.ws != nil {
		retired.server.ws.stop()
	}
	if retired.server.sse != nil {
		retired.server.sse.stop()
	}
	return retired.server.stop(ctx)
}

func httpInboundPoll() (ext.StepEvent, bool) {
	// Check HTTP queue first.
	for _, current := range allGinServers() {
		if req, cellID, ok := current.popRequest(); ok {
			payload, err := abi.EncodeHTTPRequest(req)
			if err != nil {
				current.logger.Error("encode http request", "err", err)
				return ext.StepEvent{}, false
			}
			return ext.StepEvent{
				Kind:    "http.request",
				Payload: payload,
				ID:      req.ID,
				CellID:  cellID,
			}, true
		}
	}

	// Then check WebSocket events.
	for _, current := range allGinServers() {
		if current.ws != nil {
			if wev, ok := current.ws.popEvent(); ok {
				ev, err := abi.DecodeStepEvent(wev.data)
				if err != nil {
					current.ws.logger.Error("decode ws step event", "err", err)
					return ext.StepEvent{}, false
				}
				return ext.StepEvent{
					Kind:    ev.Kind,
					Payload: ev.Payload,
					CellID:  wev.cellID,
				}, true
			}
		}
	}

	return ext.StepEvent{}, false
}

func httpInboundFinalize(id uint64) {
	for _, current := range allGinServers() {
		current.finalize(id)
	}
}

// =====================================================================
// Capability bindings: transport.http.inbound
// =====================================================================

func httpInboundRegister(b wazero.HostModuleBuilder, cell ext.Cell) error {
	cellID := ext.CellIDOf(cell)
	scope := ext.ScopeOf(cell)
	cellServer := resolveGinServerForCell(cellID, scope, "")
	if cellServer == nil {
		return errors.New("transport.http.inbound is not initialized for application scope")
	}
	// http_listen(addr) — cell declares an additional listen address.
	// If it matches the default HTTP_PORT-derived addr, it's a no-op.
	// Otherwise an additional http.Server is started sharing the same
	// Gin engine. Multiple cells calling the same addr share one
	// listener; stop() tears them all down.
	b.NewFunctionBuilder().
		WithFunc(func(_ context.Context, m api.Module, reqPtr, reqLen uint32) uint32 {
			if reqLen == 0 {
				return 1
			}
			data, ok := m.Memory().Read(reqPtr, reqLen)
			if !ok {
				return 2
			}
			var reg struct {
				Addr string `msgpack:"addr"`
			}
			if err := msgpack.Unmarshal(data, &reg); err != nil {
				return 3
			}
			if reg.Addr == "" {
				return 4
			}
			if !scope.IsLegacy() && scopedEndpointMode() {
				if resolveGinServerForCell(cellID, scope, reg.Addr) == nil {
					return 5
				}
				return 0
			}
			if err := cellServer.ensureAltListener(reg.Addr); err != nil {
				cellServer.logger.Error("http_listen bind failed", "addr", reg.Addr, "err", err)
				return 5
			}
			return 0
		}).
		Export("http_listen")

	b.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, reqPtr, reqLen uint32) uint32 {
			if reqLen == 0 {
				return 1
			}
			data, ok := m.Memory().Read(reqPtr, reqLen)
			if !ok {
				return 2
			}
			var reg struct {
				Method string `msgpack:"method"`
				Path   string `msgpack:"path"`
			}
			if err := msgpack.Unmarshal(data, &reg); err != nil {
				return 3
			}
			if err := cellServer.registerRoute(cellID, reg.Method, reg.Path); err != nil {
				return 4
			}
			return 0
		}).
		Export("http_register")

	b.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, respPtr, respLen uint32) uint32 {
			if respLen == 0 {
				return 1
			}
			data, ok := m.Memory().Read(respPtr, respLen)
			if !ok {
				return 2
			}
			resp, err := abi.DecodeHTTPResponse(data)
			if err != nil {
				return 3
			}
			if err := cellServer.respond(resp); err != nil {
				return 4
			}
			return 0
		}).
		Export("http_respond")

	return nil
}

func httpInboundStub(b wazero.HostModuleBuilder, _ ext.Cell) error {
	b.NewFunctionBuilder().
		WithFunc(func(_ context.Context, _ api.Module, _, _ uint32) uint32 { return 99 }).
		Export("http_listen")
	b.NewFunctionBuilder().
		WithFunc(func(_ context.Context, _ api.Module, _, _ uint32) uint32 { return 99 }).
		Export("http_register")
	b.NewFunctionBuilder().
		WithFunc(func(_ context.Context, _ api.Module, _, _ uint32) uint32 { return 99 }).
		Export("http_respond")
	return nil
}

// =====================================================================
// Capability bindings: transport.http.outbound
// =====================================================================

func httpOutboundRegister(b wazero.HostModuleBuilder, cell ext.Cell) error {
	cellID := ext.CellIDOf(cell)
	logger := slog.Default()
	if cellServer := existingGinServerForCell(cellID, ext.ScopeOf(cell)); cellServer != nil {
		logger = cellServer.logger
	}
	cellFetcher := fetcherForCell(cellID, logger)
	b.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, reqPtr, reqLen, respPtrOut, respLenOut uint32) uint32 {
			if reqLen == 0 {
				return 1
			}
			data, ok := m.Memory().Read(reqPtr, reqLen)
			if !ok {
				return 2
			}
			req, err := abi.DecodeHTTPFetchRequest(data)
			if err != nil {
				return 3
			}

			resp, err := cellFetcher.do(ctx, req)
			if err != nil {
				return 4
			}

			respBytes, err := abi.EncodeHTTPResponse(resp)
			if err != nil {
				return 5
			}

			allocFn := m.ExportedFunction("pulp_alloc")
			if allocFn == nil {
				return 6
			}
			results, err := allocFn.Call(ctx, uint64(len(respBytes)))
			if err != nil || len(results) == 0 {
				return 7
			}
			respPtr := uint32(results[0])
			if respPtr == 0 {
				return 7
			}

			if !m.Memory().Write(respPtr, respBytes) {
				return 8
			}
			if !m.Memory().WriteUint32Le(respPtrOut, respPtr) {
				return 8
			}
			if !m.Memory().WriteUint32Le(respLenOut, uint32(len(respBytes))) {
				return 8
			}
			return 0
		}).
		Export("http_fetch")
	return nil
}

func httpOutboundStub(b wazero.HostModuleBuilder, _ ext.Cell) error {
	b.NewFunctionBuilder().
		WithFunc(func(_ context.Context, _ api.Module, _, _, _, _ uint32) uint32 { return 99 }).
		Export("http_fetch")
	return nil
}

// =====================================================================
// Capability bindings: transport.ws.inbound
// =====================================================================

func wsInboundRegister(b wazero.HostModuleBuilder, cell ext.Cell) error {
	cellID := ext.CellIDOf(cell)
	cellServer := resolveGinServerForCell(cellID, ext.ScopeOf(cell), "")
	if cellServer == nil || cellServer.ws == nil {
		return errors.New("transport.ws.inbound is not initialized for application scope")
	}
	b.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, pathPtr, pathLen uint32) uint32 {
			if pathLen == 0 {
				return 1
			}
			data, ok := m.Memory().Read(pathPtr, pathLen)
			if !ok {
				return 2
			}
			if err := cellServer.registerWSRoute(cellID, string(data)); err != nil {
				return 4
			}
			return 0
		}).
		Export("ws_register")

	b.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, reqPtr, reqLen uint32) uint32 {
			if reqLen == 0 {
				return 1
			}
			data, ok := m.Memory().Read(reqPtr, reqLen)
			if !ok {
				return 2
			}
			req, err := abi.DecodeWSSendRequest(data)
			if err != nil {
				return 3
			}
			if err := cellServer.ws.send(ctx, req); err != nil {
				return 4
			}
			return 0
		}).
		Export("ws_send")

	b.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, reqPtr, reqLen uint32) uint32 {
			if reqLen == 0 {
				return 1
			}
			data, ok := m.Memory().Read(reqPtr, reqLen)
			if !ok {
				return 2
			}
			req, err := abi.DecodeWSCloseRequest(data)
			if err != nil {
				return 3
			}
			if err := cellServer.ws.close(req); err != nil {
				return 4
			}
			return 0
		}).
		Export("ws_close")

	return nil
}

func wsInboundStub(b wazero.HostModuleBuilder, _ ext.Cell) error {
	b.NewFunctionBuilder().
		WithFunc(func(_ context.Context, _ api.Module, _, _ uint32) uint32 { return 99 }).
		Export("ws_register")
	b.NewFunctionBuilder().
		WithFunc(func(_ context.Context, _ api.Module, _, _ uint32) uint32 { return 99 }).
		Export("ws_send")
	b.NewFunctionBuilder().
		WithFunc(func(_ context.Context, _ api.Module, _, _ uint32) uint32 { return 99 }).
		Export("ws_close")
	return nil
}

// =====================================================================
// Capability bindings: transport.sse
// =====================================================================

func sseRegister(b wazero.HostModuleBuilder, cell ext.Cell) error {
	cellID := ext.CellIDOf(cell)
	cellServer := resolveGinServerForCell(cellID, ext.ScopeOf(cell), "")
	if cellServer == nil || cellServer.sse == nil {
		return errors.New("transport.sse is not initialized for application scope")
	}
	b.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, pathPtr, pathLen uint32) uint32 {
			if pathLen == 0 {
				return 1
			}
			data, ok := m.Memory().Read(pathPtr, pathLen)
			if !ok {
				return 2
			}
			if err := cellServer.registerSSERoute(cellID, string(data)); err != nil {
				return 4
			}
			return 0
		}).
		Export("sse_register")

	b.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, reqPtr, reqLen uint32) uint32 {
			if reqLen == 0 {
				return 1
			}
			data, ok := m.Memory().Read(reqPtr, reqLen)
			if !ok {
				return 2
			}
			req, err := abi.DecodeSSEEmitRequest(data)
			if err != nil {
				return 3
			}
			if err := cellServer.sse.emit(req); err != nil {
				return 4
			}
			return 0
		}).
		Export("sse_emit")

	// sse_has_subscribers(path_ptr, path_len, out_count_ptr) — cell
	// passes the concrete path; host writes the number of currently
	// connected clients into the uint32 at out_count_ptr.
	b.NewFunctionBuilder().
		WithFunc(func(_ context.Context, m api.Module, pathPtr, pathLen, outCountPtr uint32) uint32 {
			if pathLen == 0 {
				return 1
			}
			data, ok := m.Memory().Read(pathPtr, pathLen)
			if !ok {
				return 2
			}
			count := cellServer.sse.hasSubscribers(string(data))
			if !m.Memory().WriteUint32Le(outCountPtr, count) {
				return 8
			}
			return 0
		}).
		Export("sse_has_subscribers")

	return nil
}

func sseStub(b wazero.HostModuleBuilder, _ ext.Cell) error {
	b.NewFunctionBuilder().
		WithFunc(func(_ context.Context, _ api.Module, _, _ uint32) uint32 { return 99 }).
		Export("sse_register")
	b.NewFunctionBuilder().
		WithFunc(func(_ context.Context, _ api.Module, _, _ uint32) uint32 { return 99 }).
		Export("sse_emit")
	b.NewFunctionBuilder().
		WithFunc(func(_ context.Context, _ api.Module, _, _, _ uint32) uint32 { return 99 }).
		Export("sse_has_subscribers")
	return nil
}
