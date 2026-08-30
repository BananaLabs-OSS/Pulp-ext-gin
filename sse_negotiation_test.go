package ginext

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/BananaLabs-OSS/Pulp/abi"
)

func TestSSERouteDispatchesOrdinaryGETToCellFallback(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := newGinServer("127.0.0.1:0", logger)
	server.attachSSE(newSSEServer(logger))
	if err := server.registerSSERoute("events-cell", "/orchestration/events"); err != nil {
		t.Fatal(err)
	}
	// The regular route is deliberately registered second, matching
	// Bananagine. Gin keeps the first SSE-owned route, whose negotiation must
	// still dispatch non-SSE requests through the cell.
	if err := server.registerRoute("events-cell", http.MethodGet, "/orchestration/events"); err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "/orchestration/events?limit=1", nil)
	request.Header.Set("Accept", "application/json")
	recorder := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		server.engine.ServeHTTP(recorder, request)
		close(done)
	}()

	deadline := time.Now().Add(time.Second)
	for {
		inflight, cellID, ok := server.popRequest()
		if ok {
			if cellID != "events-cell" {
				t.Fatalf("request cell = %q", cellID)
			}
			if err := server.respond(abi.HTTPResponse{ID: inflight.ID, Status: http.StatusOK, Body: []byte("[]")}); err != nil {
				t.Fatal(err)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("ordinary GET was hijacked as an SSE stream")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("ordinary GET did not complete")
	}
	if recorder.Code != http.StatusOK || recorder.Body.String() != "[]" {
		t.Fatalf("response = %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestSSERouteKeepsEventStreamRequestsStreaming(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := newGinServer("127.0.0.1:0", logger)
	server.attachSSE(newSSEServer(logger))
	if err := server.registerSSERoute("events-cell", "/orchestration/events"); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	request := httptest.NewRequest(http.MethodGet, "/orchestration/events", nil).WithContext(ctx)
	request.Header.Set("Accept", "text/event-stream; charset=utf-8")
	recorder := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		server.engine.ServeHTTP(recorder, request)
		close(done)
	}()

	deadline := time.Now().Add(time.Second)
	for server.sse.hasSubscribers("/orchestration/events") != 1 {
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("event-stream request did not subscribe")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("event-stream request did not stop after cancellation")
	}
	if got := recorder.Header().Get("Content-Type"); got != "text/event-stream" {
		t.Fatalf("content type = %q", got)
	}
}
