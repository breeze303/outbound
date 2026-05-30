package grpc

import "testing"

func TestCleanScopedClientConnectionCacheOnlyDeletesNamespace(t *testing.T) {
	globalCCAccess.Lock()
	globalCCMap = map[string]*clientConnMeta{
		transportCacheKey("ns-a", "server-a:443"): {},
		transportCacheKey("ns-b", "server-b:443"): {},
		transportCacheKey("", "server-c:443"):     {},
	}
	globalCCAccess.Unlock()

	CleanScopedClientConnectionCache("ns-a")

	globalCCAccess.Lock()
	defer globalCCAccess.Unlock()
	if _, ok := globalCCMap[transportCacheKey("ns-a", "server-a:443")]; ok {
		t.Fatal("ns-a entry was not removed")
	}
	if _, ok := globalCCMap[transportCacheKey("ns-b", "server-b:443")]; !ok {
		t.Fatal("ns-b entry was removed by scoped cleanup")
	}
	if _, ok := globalCCMap[transportCacheKey("", "server-c:443")]; !ok {
		t.Fatal("global entry was removed by scoped cleanup")
	}
}
