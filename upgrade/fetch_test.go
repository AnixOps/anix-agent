package upgrade

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AnixOps/anix-control/sdk/agentcontrol"
)

// download takes the control connection first and the https URL when it
// fails.
func TestDownloadFetchesOnTheControlConnectionFirst(t *testing.T) {
	served := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		served++
		_, _ = w.Write([]byte("https"))
	}))
	defer server.Close()
	a := &Agent{Dir: t.TempDir(), HTTPClient: server.Client()}
	read := func(ctx context.Context) string {
		t.Helper()
		path, err := a.download(ctx, agentcontrol.ReleaseKindAgent, "v5.1.0", server.URL, "a.zip", "", 5)
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	grpc := WithFetch(context.Background(), func(_ context.Context, kind, version, asset string, size int64) ([]byte, error) {
		if kind != agentcontrol.ReleaseKindAgent || version != "v5.1.0" || asset != "a.zip" || size != 5 {
			t.Errorf("fetch got %s %s %s %d", kind, version, asset, size)
		}
		return []byte("grpc!"), nil
	})
	if got := read(grpc); got != "grpc!" || served != 0 {
		t.Fatalf("got %q with %d https requests, want the control connection's bytes", got, served)
	}
	broken := WithFetch(context.Background(), func(context.Context, string, string, string, int64) ([]byte, error) {
		return nil, errors.New("session gone")
	})
	if got := read(broken); got != "https" || served != 1 {
		t.Fatalf("got %q with %d https requests, want the https fallback", got, served)
	}
}

// A control-connection download that stalls gets half the operation's time,
// so the https fallback still runs before the deadline.
func TestDownloadStalledFetchLeavesTimeForHTTPS(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("https"))
	}))
	defer server.Close()
	a := &Agent{Dir: t.TempDir(), HTTPClient: server.Client()}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	stalled := WithFetch(ctx, func(ctx context.Context, _, _, _ string, _ int64) ([]byte, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	path, err := a.download(stalled, agentcontrol.ReleaseKindAgent, "v5.1.0", server.URL, "a.zip", "", 5)
	if err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(path); string(data) != "https" {
		t.Fatalf("got %q, want the https fallback", data)
	}
}

// The region relay's cache goes first, asked by SHA-256 with the release
// URL as its source; a copy with the wrong hash falls through to the next
// source.
func TestDownloadAsksTheReleaseCacheFirst(t *testing.T) {
	const body = "cache"
	sum := sha256Of(body)
	origin := "https://github.com/AnixOps/anix-agent/releases/download/v5.1.0/a.zip"
	var cacheAnswer atomic.Value
	cacheAnswer.Store(body)
	cache := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sha256/"+sum || r.URL.Query().Get("src") != origin {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(cacheAnswer.Load().(string)))
	}))
	defer cache.Close()
	a := &Agent{Dir: t.TempDir(), HTTPClient: cache.Client()}
	a.SetCaches([]string{"http://insecure.example", cache.URL + "/"})
	fetched := 0
	ctx := WithFetch(context.Background(), func(context.Context, string, string, string, int64) ([]byte, error) {
		fetched++
		return []byte("grpc!"), nil
	})
	read := func() string {
		t.Helper()
		path, err := a.download(ctx, agentcontrol.ReleaseKindAgent, "v5.1.0", origin, "a.zip", sum, 5)
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	if got := read(); got != body || fetched != 0 {
		t.Fatalf("got %q after %d control fetches, want the cache's bytes", got, fetched)
	}
	cacheAnswer.Store("evil!")
	if got := read(); got != "grpc!" || fetched != 1 {
		t.Fatalf("got %q after %d control fetches, want the control connection after a bad cached copy", got, fetched)
	}
	entries, err := os.ReadDir(a.Dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if data, _ := os.ReadFile(filepath.Join(a.Dir, entry.Name())); string(data) == "evil!" {
			t.Fatal("the bad cached copy was left in the staging directory")
		}
	}
}

func TestSetCachesKeepsHTTPSOnly(t *testing.T) {
	a := &Agent{}
	a.SetCaches([]string{"", "http://relay.example", "https://user:pw@relay.example", "https://relay.example/?x=1", " https://relay-1.example:8443/ "})
	if got := a.releaseCaches(); len(got) != 1 || got[0] != "https://relay-1.example:8443" {
		t.Fatalf("caches = %v", got)
	}
}

func sha256Of(data string) string {
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}
