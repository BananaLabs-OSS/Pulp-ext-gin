package ginext

import (
	"testing"

	"github.com/BananaLabs-OSS/Pulp/ext"
)

func TestTransportCapabilitiesDeclareGinProvider(t *testing.T) {
	t.Parallel()

	want := map[string]bool{
		"transport.http.inbound":  false,
		"transport.http.outbound": false,
		"transport.ws.inbound":    false,
		"transport.sse":           false,
	}
	for _, capability := range ext.All() {
		if _, ok := want[capability.Name]; !ok {
			continue
		}
		if capability.Provider != "github.com/BananaLabs-OSS/Pulp-ext-gin" {
			t.Fatalf("provider for %q = %q, want github.com/BananaLabs-OSS/Pulp-ext-gin", capability.Name, capability.Provider)
		}
		want[capability.Name] = true
	}
	for name, found := range want {
		if !found {
			t.Errorf("capability %q was not registered", name)
		}
	}
}
