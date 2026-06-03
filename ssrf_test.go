package ginext

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/BananaLabs-OSS/Pulp/abi"
)

// newTestFetcher builds a fetcher with the given HTTP_FETCH_ALLOW value.
func newTestFetcher(t *testing.T, allow string) *fetcher {
	t.Helper()
	t.Setenv("HTTP_FETCH_ALLOW", allow)
	return newFetcher(slog.Default())
}

// TestSSRFBlocksPrivate verifies the egress guard refuses to dial
// loopback / link-local (cloud-metadata) / private targets. These are the
// SSRF sinks the production-wired http_fetch must never reach.
func TestSSRFBlocksPrivate(t *testing.T) {
	f := newTestFetcher(t, "")

	cases := []struct {
		name string
		url  string
	}{
		{"loopback-v4", "http://127.0.0.1/"},
		{"loopback-name", "http://localhost/"},
		{"cloud-metadata", "http://169.254.169.254/latest/meta-data/"},
		{"rfc1918-10", "http://10.0.0.1/"},
		{"rfc1918-192", "http://192.168.1.1/"},
		{"rfc1918-172", "http://172.16.0.1/"},
		{"unspecified", "http://0.0.0.0/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := f.do(context.Background(), abi.HTTPFetchRequest{URL: tc.url})
			if err == nil {
				t.Fatalf("expected SSRF guard to block %s, got nil error", tc.url)
			}
			if !strings.Contains(err.Error(), "blocked") {
				t.Fatalf("expected a blocked-target error for %s, got: %v", tc.url, err)
			}
		})
	}
}

// TestSSRFRejectsNonHTTPScheme verifies the scheme allowlist refuses
// file:// and other non-http(s) schemes before any dial.
func TestSSRFRejectsNonHTTPScheme(t *testing.T) {
	f := newTestFetcher(t, "")
	for _, url := range []string{"file:///etc/passwd", "gopher://127.0.0.1/", "ftp://example.com/"} {
		_, err := f.do(context.Background(), abi.HTTPFetchRequest{URL: url})
		if err == nil {
			t.Fatalf("expected scheme guard to reject %s, got nil", url)
		}
		if !strings.Contains(err.Error(), "scheme") {
			t.Fatalf("expected a scheme error for %s, got: %v", url, err)
		}
	}
}

// TestSSRFAllowsPublic verifies legit public fetches still work. We stand
// up a local test server but explicitly allowlist its host so the guard
// does not block the loopback bind the httptest server uses — this proves
// the allow path AND that a normal request round-trips.
func TestSSRFAllowsPublic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	host := srv.Listener.Addr().String() // host:port (127.0.0.1:NNNNN)
	f := newTestFetcher(t, host)

	resp, err := f.do(context.Background(), abi.HTTPFetchRequest{URL: srv.URL})
	if err != nil {
		t.Fatalf("allowlisted fetch failed: %v", err)
	}
	if resp.Status != http.StatusOK || string(resp.Body) != "ok" {
		t.Fatalf("unexpected response: status=%d body=%q", resp.Status, resp.Body)
	}
}

// TestSSRFAllowlistDoesNotLeakOnRedirect verifies an allowlisted host that
// redirects to a NON-allowlisted private target is still blocked on the
// redirect hop (the exemption is per-dial, not pinned to the request).
func TestSSRFAllowlistDoesNotLeakOnRedirect(t *testing.T) {
	// Redirect target: a different loopback host:port that is NOT allowlisted.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("internal-secret"))
	}))
	defer target.Close()

	// Entry server redirects to the private target. Only the entry server is
	// allowlisted.
	entry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/", http.StatusFound)
	}))
	defer entry.Close()

	f := newTestFetcher(t, entry.Listener.Addr().String())

	_, err := f.do(context.Background(), abi.HTTPFetchRequest{URL: entry.URL})
	if err == nil {
		t.Fatal("expected redirect to non-allowlisted loopback target to be blocked, got nil")
	}
	if !strings.Contains(err.Error(), "blocked") {
		t.Fatalf("expected a blocked-target error on the redirect hop, got: %v", err)
	}
}

// ipBlocked sanity: the helper itself classifies ranges correctly.
func TestIPBlockedClassification(t *testing.T) {
	blocked := []string{"127.0.0.1", "169.254.169.254", "10.1.2.3", "192.168.0.1", "172.16.5.5", "::1", "fc00::1", "0.0.0.0"}
	for _, s := range blocked {
		if ip := net.ParseIP(s); !ipBlocked(ip) {
			t.Fatalf("expected %s to be blocked", s)
		}
	}
	allowed := []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"}
	for _, s := range allowed {
		if ip := net.ParseIP(s); ipBlocked(ip) {
			t.Fatalf("expected %s to be allowed", s)
		}
	}
}
