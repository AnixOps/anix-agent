package forward

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRetireNftablesDeletesTheTableAndQdisc(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	nft := filepath.Join(dir, "nft")
	tc := filepath.Join(dir, "tc")
	script := func(body string) string { return "#!/bin/sh\necho \"$0 $*\" >> '" + log + "'\n" + body + "\n" }
	if err := os.WriteFile(nft, []byte(script("exit 0")), 0o755); err != nil { // #nosec G306 -- a test script
		t.Fatal(err)
	}
	showing := "echo 'qdisc noqueue 0: dev lo root refcnt 2'; echo 'qdisc htb af00: dev eth0 root refcnt 2 r2q 10'; echo 'qdisc fq_codel 0: dev eth1 root refcnt 2'"
	if err := os.WriteFile(tc, []byte(script("case \"$*\" in \"qdisc show\") "+showing+";; esac")), 0o755); err != nil { // #nosec G306 -- a test script
		t.Fatal(err)
	}
	RetireNftables(t.Context(), NftablesSettings{NFT: nft, TC: tc})
	data, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	calls := string(data)
	for _, want := range []string{" delete table inet anixops_fwd", " qdisc del dev eth0 root handle af00:"} {
		if !strings.Contains(calls, want) {
			t.Errorf("missing %q in:\n%s", want, calls)
		}
	}
	if strings.Contains(calls, "dev eth1") || strings.Contains(calls, "dev lo") {
		t.Errorf("deleted a qdisc it does not own:\n%s", calls)
	}
}

func TestRetireNftablesIsQuietWithoutTheBinaries(t *testing.T) {
	RetireNftables(t.Context(), NftablesSettings{NFT: "/nonexistent/nft", TC: "/nonexistent/tc"})
}
