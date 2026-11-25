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
	"strings"
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
	a.SetRoute("proxy-1", RelayRoute{Caches: []string{"http://insecure.example", cache.URL + "/"}})
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

func TestSetRouteKeepsHTTPSOnly(t *testing.T) {
	a := &Agent{}
	a.SetRoute("proxy-1", RelayRoute{Caches: []string{"", "http://relay.example", "https://user:pw@relay.example", "https://relay.example/?x=1", " https://relay-1.example:8443/ "}})
	if got := a.releaseCaches(); len(got) != 1 || got[0] != "https://relay-1.example:8443" {
		t.Fatalf("caches = %v", got)
	}
}

// Every node identity of the process shares the Agent: one identity's
// route must not replace or clear another's.
func TestSetRouteKeepsEveryIdentitysCaches(t *testing.T) {
	a := &Agent{}
	a.SetRoute("proxy-1", RelayRoute{Caches: []string{"https://relay-1.example:8443", "https://relay-2.example:8443"}})
	a.SetRoute("forward-2", RelayRoute{Caches: []string{"https://relay-2.example:8443", "https://relay-3.example:8443"}})
	a.SetRoute("proxy-3", RelayRoute{})
	want := []string{"https://relay-2.example:8443", "https://relay-3.example:8443", "https://relay-1.example:8443"}
	if got := a.releaseCaches(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("caches = %v, want %v", got, want)
	}
	a.SetRoute("forward-2", RelayRoute{})
	if got := a.releaseCaches(); len(got) != 2 || got[0] != "https://relay-1.example:8443" {
		t.Fatalf("after removing forward-2, caches = %v", got)
	}
}

// A node that reaches Control only through relays does not download a
// release from Control's host directly when the caches and the control
// connection failed.
func TestDownloadRefusesControlsHostBehindRelays(t *testing.T) {
	var direct atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		direct.Add(1)
		_, _ = w.Write([]byte("files"))
	}))
	defer server.Close()
	a := &Agent{Dir: t.TempDir(), HTTPClient: server.Client()}
	a.SetRoute("proxy-1", RelayRoute{ControlHosts: []string{"127.0.0.1."}})
	_, err := a.download(context.Background(), agentcontrol.ReleaseKindAgent, "v5.1.0", server.URL+"/a.zip", "a.zip", sha256Of("files"), 5)
	if err == nil || direct.Load() != 0 {
		t.Fatalf("download = %v after %d direct requests, want a refusal without one", err, direct.Load())
	}
	a.SetRoute("proxy-1", RelayRoute{})
	if _, err := a.download(context.Background(), agentcontrol.ReleaseKindAgent, "v5.1.0", server.URL+"/a.zip", "a.zip", sha256Of("files"), 5); err != nil || direct.Load() != 1 {
		t.Fatalf("without relays, download = %v after %d requests", err, direct.Load())
	}
}

// A cache that stalls is given up after releaseCacheTimeout even without
// a deadline, and the next source runs.
func TestDownloadBoundsEachCache(t *testing.T) {
	saved := releaseCacheTimeout
	releaseCacheTimeout = 100 * time.Millisecond
	t.Cleanup(func() { releaseCacheTimeout = saved })
	stall := make(chan struct{})
	cache := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-stall:
		case <-r.Context().Done():
		}
	}))
	defer cache.Close()
	defer close(stall)
	a := &Agent{Dir: t.TempDir(), HTTPClient: cache.Client()}
	a.SetRoute("proxy-1", RelayRoute{Caches: []string{cache.URL}})
	ctx := WithFetch(context.Background(), func(context.Context, string, string, string, int64) ([]byte, error) {
		return []byte("grpc!"), nil
	})
	started := time.Now()
	path, err := a.download(ctx, agentcontrol.ReleaseKindAgent, "v5.1.0", "https://github.com/x/a.zip", "a.zip", sha256Of("grpc!"), 5)
	if err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(path); string(data) != "grpc!" {
		t.Fatalf("got %q, want the control connection's bytes", data)
	}
	if waited := time.Since(started); waited > 5*time.Second {
		t.Fatalf("the stalled cache held the download for %s", waited)
	}
}

func sha256Of(data string) string {
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}
