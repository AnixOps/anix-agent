package conf

import (
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
