package machinetelemetry

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// exactControlConfig is the document of anix-control
// docs/architecture/package-reports.md and systemdreport/config.go.
const exactControlConfig = `{
  "interval_seconds": 30,
  "systemd_services": {
    "nodes": {
      "12": { "enabled": true, "include": ["nginx*.service"], "exclude": ["*-debug.service"] }
    }
  }
}`

func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	return path
}

func TestLoadConfigAcceptsSystemdServices(t *testing.T) {
	config, err := LoadConfig(writeConfig(t, exactControlConfig))
	require.NoError(t, err)
	assert.Equal(t, 30, config.IntervalSeconds)
	node := config.Services.Node(12)
	assert.True(t, node.Enabled)
	assert.Equal(t, []string{"nginx*.service"}, node.Include)
	assert.Equal(t, []string{"*-debug.service"}, node.Exclude)
	assert.True(t, node.Selected("nginx.service"))
	assert.False(t, node.Selected("nginx-debug.service"))
	assert.False(t, config.Services.Node(13).Enabled, "another node stays off")
	assert.False(t, config.Services.Node(0).Enabled)

	for _, document := range []string{`{}`, `{"systemd_services": null}`, `{"systemd_services": {}}`, `{"systemd_services": {"nodes": {}}}`} {
		config, err := LoadConfig(writeConfig(t, document))
		require.NoError(t, err, document)
		assert.False(t, config.Services.Node(12).Enabled, document)
	}
}

func TestLoadConfigAcceptsTheLargestServicesDocument(t *testing.T) {
	var builder strings.Builder
	builder.WriteString(`{"interval_seconds":30,"systemd_services":{"nodes":{`)
	for node := 1; node <= MaxServicesNodes; node++ {
		if node > 1 {
			builder.WriteByte(',')
		}
		fmt.Fprintf(&builder, `"%d":{"enabled":true,"exclude":["*-debug.service"]}`, node)
	}
	builder.WriteString(`}}}`)
	require.Greater(t, builder.Len(), 64<<10, "more than the old 64 KiB limit")
	config, err := LoadConfig(writeConfig(t, builder.String()))
	require.NoError(t, err)
	assert.True(t, config.Services.Node(MaxServicesNodes).Enabled)
}

func TestLoadConfigRefusesMalformedSystemdServices(t *testing.T) {
	tooManyGlobs := make([]string, MaxServicesGlobs+1)
	for index := range tooManyGlobs {
		tooManyGlobs[index] = fmt.Sprintf("%q", fmt.Sprintf("u%d.service", index))
	}
	var tooManyNodes strings.Builder
	tooManyNodes.WriteString(`{"systemd_services":{"nodes":{`)
	for node := 1; node <= MaxServicesNodes+1; node++ {
		if node > 1 {
			tooManyNodes.WriteByte(',')
		}
		fmt.Fprintf(&tooManyNodes, `"%d":{"enabled":false}`, node)
	}
	tooManyNodes.WriteString(`}}}`)
	for name, document := range map[string]string{
		"settings a list":    `{"systemd_services": []}`,
		"settings a string":  `{"systemd_services": "on"}`,
		"unknown field":      `{"systemd_services": {"nodes": {}, "all": true}}`,
		"unknown node field": `{"systemd_services": {"nodes": {"1": {"enabled": true, "description": "x"}}}}`,
		"node id zero":       `{"systemd_services": {"nodes": {"0": {"enabled": true}}}}`,
		"node id padded":     `{"systemd_services": {"nodes": {"012": {"enabled": true}}}}`,
		"node id a name":     `{"systemd_services": {"nodes": {"edge": {"enabled": true}}}}`,
		"node id too large":  `{"systemd_services": {"nodes": {"4294967296": {"enabled": true}}}}`,
		"enabled a string":   `{"systemd_services": {"nodes": {"1": {"enabled": "yes"}}}}`,
		"bad glob":           `{"systemd_services": {"nodes": {"1": {"enabled": true, "include": ["nginx["]}}}}`,
		"empty glob":         `{"systemd_services": {"nodes": {"1": {"enabled": true, "exclude": [""]}}}}`,
		"glob with a space":  `{"systemd_services": {"nodes": {"1": {"enabled": true, "exclude": ["a b"]}}}}`,
		"glob with a slash":  `{"systemd_services": {"nodes": {"1": {"enabled": true, "exclude": ["a/b"]}}}}`,
		"glob too long":      `{"systemd_services": {"nodes": {"1": {"enabled": true, "exclude": ["` + strings.Repeat("a", MaxServicesGlobLength+1) + `"]}}}}`,
		"too many globs":     `{"systemd_services": {"nodes": {"1": {"enabled": true, "include": [` + strings.Join(tooManyGlobs, ",") + `]}}}}`,
		"too many nodes":     tooManyNodes.String(),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := LoadConfig(writeConfig(t, document))
			require.ErrorIs(t, err, ErrInvalidServicesConfig)
		})
	}
}

func TestLoadConfigStillRefusesOtherUnknownKeys(t *testing.T) {
	for _, document := range []string{
		`{"interval_seconds":30,"systemd_services":{"nodes":{}},"command":"id"}`,
		`{"systemd_service":{"nodes":{}}}`,
		`{"SystemdServices":{"nodes":{}},"extra":1}`,
	} {
		_, err := LoadConfig(writeConfig(t, document))
		require.ErrorContains(t, err, "unknown field", document)
	}
	// interval_seconds keeps its bounds next to systemd_services.
	_, err := LoadConfig(writeConfig(t, `{"interval_seconds":4,"systemd_services":{"nodes":{}}}`))
	require.ErrorContains(t, err, "at least 5")
}

func TestValidServicesGlob(t *testing.T) {
	for _, glob := range []string{"*", "nginx.service", "nginx*.service", "ssh?.service", "[a-c]*.service", "[^x]*", `a@b\x2d1.service`} {
		assert.True(t, validServicesGlob(glob), glob)
	}
	for _, glob := range []string{"", "[", "a[", "x\\", "a b", "a/b", "ü.service"} {
		assert.False(t, validServicesGlob(glob), glob)
	}
}

func TestParseNodeID(t *testing.T) {
	for value, want := range map[string]uint64{"": 0, "1": 1, "12": 12, "4294967295": 4294967295} {
		got, err := ParseNodeID(value)
		require.NoError(t, err, value)
		assert.Equal(t, want, got, value)
	}
	for _, value := range []string{"0", "012", "-1", "edge", "4294967296", " 12", "1.5"} {
		_, err := ParseNodeID(value)
		require.Error(t, err, value)
	}
}
