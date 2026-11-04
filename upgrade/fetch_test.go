package upgrade

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

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
		path, err := a.download(ctx, agentcontrol.ReleaseKindAgent, "v5.1.0", server.URL, "a.zip", 5)
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
