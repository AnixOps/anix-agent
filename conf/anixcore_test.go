package conf

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// The unit runs under ProtectSystem=strict: the configuration directory is
// read only, so anixcore's generated config goes below RuntimeDirectory.
func TestAnixcoreRuntimeDirIsWritable(t *testing.T) {
	dir := NewAnixcoreConfig().RuntimeDir
	assert.True(t, strings.HasPrefix(dir, DefaultRuntimeRoot+"/"), dir)
}

func TestRetiredCoreRunsInstalledAnxNode(t *testing.T) {
	for _, installed := range []bool{true, false} {
		previous := installedAnxNode
		installedAnxNode = func() bool { return installed }
		var core CoreConfig
		err := json.Unmarshal([]byte(`{"Type":"xray"}`), &core)
		installedAnxNode = previous
		if err != nil {
			t.Fatal(err)
		}
		if core.Type != "anixcore" || core.AnixcoreConfig == nil {
			t.Fatalf("installed=%v: core = %+v", installed, core)
		}
		wantPath, wantLine := "anixcore", false
		if installed {
			wantPath, wantLine = InstalledAnxNodePath, true
		}
		if core.AnixcoreConfig.BinaryPath != wantPath || core.AnixcoreConfig.AnxLine != wantLine {
			t.Fatalf("installed=%v: BinaryPath %q AnxLine %v, want %q %v", installed, core.AnixcoreConfig.BinaryPath, core.AnixcoreConfig.AnxLine, wantPath, wantLine)
		}
	}
}
