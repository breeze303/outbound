package meek

import (
	"net/http"
	"testing"
)

type testRoundTripper struct{}

func (testRoundTripper) RoundTrip(*http.Request) (*http.Response, error) { return nil, nil }

func TestCleanScopedRoundTripperCacheOnlyDeletesNamespace(t *testing.T) {
	globalRoundTripperCacheAccess.Lock()
	globalRoundTripperCacheMap = map[string]http.RoundTripper{
		roundTripperCacheKey("ns-a", "server-a:443"): testRoundTripper{},
		roundTripperCacheKey("ns-b", "server-b:443"): testRoundTripper{},
		roundTripperCacheKey("", "server-c:443"):     testRoundTripper{},
	}
	globalRoundTripperCacheAccess.Unlock()

	CleanScopedRoundTripperCache("ns-a")

	globalRoundTripperCacheAccess.Lock()
	defer globalRoundTripperCacheAccess.Unlock()
	if _, ok := globalRoundTripperCacheMap[roundTripperCacheKey("ns-a", "server-a:443")]; ok {
		t.Fatal("ns-a entry was not removed")
	}
	if _, ok := globalRoundTripperCacheMap[roundTripperCacheKey("ns-b", "server-b:443")]; !ok {
		t.Fatal("ns-b entry was removed by scoped cleanup")
	}
	if _, ok := globalRoundTripperCacheMap[roundTripperCacheKey("", "server-c:443")]; !ok {
		t.Fatal("global entry was removed by scoped cleanup")
	}
}
