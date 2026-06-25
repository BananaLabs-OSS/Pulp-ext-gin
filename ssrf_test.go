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
	"github.com/BananaLabs-OSS/Pulp/ssrfguard"
)

// newTestFetcher builds a fetcher with the given HTTP_FETCH_ALLOW value,
// using the ext-gin constructor which pre-seeds defaultInternalServiceHosts.
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

// TestSSRFDefaultAllowsInternalServiceHosts verifies the built-in default
// allow-set exempts Evolution's first-party internal service hostnames
// (Bananagine + minecraft-resolver) WITHOUT any HTTP_FETCH_ALLOW config, so
// Evolution -> Bananagine works out-of-box. The exemption is by exact
// hostname, checked here against the guard's HostAllowed (the same per-dial
// decision DialContext makes).
//
// This test exercises the seedHosts seeding path of ssrfguard.NewEgressGuard.
// It MUST remain in ext-gin: it proves that ext-gin's call site passes
// defaultInternalServiceHosts as seedHosts, which is the intentional
// behavioural difference between ext-gin and ext-http/ext-workers.
func TestSSRFDefaultAllowsInternalServiceHosts(t *testing.T) {
	t.Setenv("HTTP_FETCH_ALLOW", "")
	g := ssrfguard.NewEgressGuard("", defaultInternalServiceHosts)

	exempt := []string{
		"bananagine",
		"bananagine:3000",
		"minecraft-resolver",
		"minecraft-resolver:8080",
		"BANANAGINE",           // case-insensitive
		"minecraft-resolver:9", // bare name matches even on a non-default port
	}
	for _, h := range exempt {
		if !g.HostAllowed(h) {
			t.Fatalf("expected internal service host %q to be allowed by default, was blocked", h)
		}
	}
}

// TestSSRFDefaultStillBlocksArbitraryInternal verifies the default allow-set
// does NOT widen the IP block: a cell's user-supplied URL pointed at the
// cloud-metadata endpoint or an arbitrary internal IP is still refused even
// though the internal service NAMES are now exempt. Security holds.
//
// This test MUST remain in ext-gin: it proves that seeding
// defaultInternalServiceHosts does not accidentally open IP-based bypasses
// (an arbitrary 10.x or 169.254.x address, not on the exact name list, is
// still refused). Critical security regression guard.
func TestSSRFDefaultStillBlocksArbitraryInternal(t *testing.T) {
	f := newTestFetcher(t, "") // default guard, internal names exempt

	// HostAllowed must NOT match arbitrary internal IPs or other names.
	if f.guard.HostAllowed("169.254.169.254") {
		t.Fatal("metadata IP must not be on the default name allowlist")
	}
	if f.guard.HostAllowed("10.0.0.5:3000") {
		t.Fatal("arbitrary RFC-1918 IP must not be on the default name allowlist")
	}
	if f.guard.HostAllowed("evil-internal") {
		t.Fatal("an unknown internal name must not be on the default allowlist")
	}

	// And an end-to-end dial to those still errors with a blocked-target.
	cases := []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://10.0.0.5/",
		"http://192.168.1.1:3000/",
	}
	for _, url := range cases {
		_, err := f.do(context.Background(), abi.HTTPFetchRequest{URL: url})
		if err == nil {
			t.Fatalf("expected %s to stay blocked under the default allow-set, got nil", url)
		}
		if !strings.Contains(err.Error(), "blocked") {
			t.Fatalf("expected a blocked-target error for %s, got: %v", url, err)
		}
	}
}

// TestIPBlockedClassification uses ssrfguard.IPBlocked to confirm the shared
// function classifies ranges correctly, replacing the local ipBlocked call.
func TestIPBlockedClassification(t *testing.T) {
	blocked := []string{"127.0.0.1", "169.254.169.254", "10.1.2.3", "192.168.0.1", "172.16.5.5", "::1", "fc00::1", "0.0.0.0"}
	for _, s := range blocked {
		if ip := net.ParseIP(s); !ssrfguard.IPBlocked(ip) {
			t.Fatalf("expected %s to be blocked", s)
		}
	}
	allowed := []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"}
	for _, s := range allowed {
		if ip := net.ParseIP(s); ssrfguard.IPBlocked(ip) {
			t.Fatalf("expected %s to be allowed", s)
		}
	}
}
