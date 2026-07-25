package ginext

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BananaLabs-OSS/Pulp/abi"
	"github.com/BananaLabs-OSS/Pulp/ext"
)

type recordingEndpointReporter struct {
	mu    sync.Mutex
	ready []ext.Endpoint
	gone  []ext.Endpoint
}

func (r *recordingEndpointReporter) Ready(endpoint ext.Endpoint) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ready = append(r.ready, endpoint)
	return nil
}

func (r *recordingEndpointReporter) Gone(endpoint ext.Endpoint) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gone = append(r.gone, endpoint)
}

func (r *recordingEndpointReporter) snapshot() ([]ext.Endpoint, []ext.Endpoint) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]ext.Endpoint(nil), r.ready...), append([]ext.Endpoint(nil), r.gone...)
}

func testScope(t *testing.T, app, instance, cell string) ext.Scope {
	t.Helper()
	scope, err := ext.NewScope(app, instance, cell, "default")
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func setupScopedGin(t *testing.T) *recordingEndpointReporter {
	t.Helper()
	reporter := &recordingEndpointReporter{}
	if err := httpInboundSetup(ext.SetupEnv{Endpoints: reporter, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = httpInboundTeardown(context.Background()) })
	return reporter
}

func TestScopedGinApplicationsUseDistinctListenersAndRoutingIDs(t *testing.T) {
	reporter := setupScopedGin(t)
	evolution := testScope(t, "evolution", "primary", "api")
	sessions := testScope(t, "sessions", "blue", "api")
	evolutionID, sessionsID := evolution.RoutingID(), sessions.RoutingID()
	evolutionServer := resolveGinServerForCell(evolutionID, evolution, "")
	sessionsServer := resolveGinServerForCell(sessionsID, sessions, "")
	if evolutionServer == nil || sessionsServer == nil || evolutionServer == sessionsServer {
		t.Fatal("scoped applications did not receive isolated Gin servers")
	}
	if evolutionServer.ws == nil || evolutionServer.sse == nil || evolutionServer.ws == sessionsServer.ws || evolutionServer.sse == sessionsServer.sse {
		t.Fatal("scoped applications did not receive isolated WebSocket/SSE state")
	}
	if !strings.HasPrefix(evolutionServer.boundAddr, "127.0.0.1:") || !strings.HasPrefix(sessionsServer.boundAddr, "127.0.0.1:") || evolutionServer.boundAddr == sessionsServer.boundAddr {
		t.Fatalf("unexpected private endpoints evolution=%q sessions=%q", evolutionServer.boundAddr, sessionsServer.boundAddr)
	}
	if err := evolutionServer.registerRoute(evolutionID, http.MethodGet, "/owned"); err != nil {
		t.Fatal(err)
	}
	if err := sessionsServer.registerRoute(sessionsID, http.MethodGet, "/owned"); err != nil {
		t.Fatal(err)
	}

	type result struct {
		body string
		err  error
	}
	request := func(address string) <-chan result {
		out := make(chan result, 1)
		go func() {
			resp, err := http.Get("http://" + address + "/owned")
			if err != nil {
				out <- result{err: err}
				return
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			out <- result{body: string(body), err: err}
		}()
		return out
	}
	assertRoute := func(server *ginServer, wantCell, address, body string) {
		t.Helper()
		done := request(address)
		deadline := time.Now().Add(time.Second)
		for {
			req, cellID, ok := server.popRequest()
			if ok {
				if cellID != wantCell {
					t.Fatalf("event target = %q, want %q", cellID, wantCell)
				}
				if err := server.respond(abi.HTTPResponse{ID: req.ID, Status: http.StatusOK, Body: []byte(body)}); err != nil {
					t.Fatal(err)
				}
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("route did not enqueue request")
			}
			time.Sleep(time.Millisecond)
		}
		if got := <-done; got.err != nil || got.body != body {
			t.Fatalf("response = %#v, want body %q", got, body)
		}
	}
	assertRoute(evolutionServer, evolutionID, evolutionServer.boundAddr, "evolution")
	assertRoute(sessionsServer, sessionsID, sessionsServer.boundAddr, "sessions")
	ready, _ := reporter.snapshot()
	if len(ready) != 2 || ready[0].Scope.ApplicationID() == ready[1].Scope.ApplicationID() {
		t.Fatalf("Ready endpoints = %#v, want one per application", ready)
	}
}

func TestScopedGinTeardownAndRebindDoNotAffectSibling(t *testing.T) {
	reporter := setupScopedGin(t)
	evolution := testScope(t, "evolution", "primary", "api")
	sessions := testScope(t, "sessions", "blue", "api")
	evolutionServer := resolveGinServerForCell(evolution.RoutingID(), evolution, "")
	sessionsServer := resolveGinServerForCell(sessions.RoutingID(), sessions, "")
	if err := httpInboundTeardownScope(context.Background(), evolution); err != nil {
		t.Fatal(err)
	}
	if got := resolveGinServerForCell(sessions.RoutingID(), sessions, ""); got != sessionsServer {
		t.Fatal("tearing down Evolution changed Sessions listener")
	}
	probe, err := netHTTPProbe(sessionsServer.boundAddr)
	if err != nil {
		t.Fatalf("Sessions listener unavailable after Evolution teardown: %v", err)
	}
	_ = probe.Body.Close()
	recovered := resolveGinServerForCell(evolution.RoutingID(), evolution, "")
	if recovered == nil || recovered == evolutionServer || recovered.boundAddr == sessionsServer.boundAddr {
		t.Fatal("Evolution did not recover with a new isolated listener")
	}
	ready, gone := reporter.snapshot()
	if len(ready) != 3 || len(gone) != 1 || gone[0].Scope.ApplicationID() != "evolution" {
		t.Fatalf("endpoint lifecycle ready=%d gone=%#v", len(ready), gone)
	}
}

func netHTTPProbe(address string) (*http.Response, error) {
	client := &http.Client{Timeout: time.Second}
	return client.Get("http://" + address + "/not-found")
}
