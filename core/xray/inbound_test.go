package xray

import (
	"testing"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	"github.com/AnixOps/anix-agent/v5/conf"
	"github.com/stretchr/testify/require"
)

// A VLESS node whose network Control leaves empty is plain TCP, with or
// without transport settings.
func TestEmptyVLESSNetworkIsTCP(t *testing.T) {
	for name, settings := range map[string][]byte{"none": nil, "tcp settings": []byte(`{}`)} {
		t.Run(name, func(t *testing.T) {
			info := &panel.NodeInfo{
				Type:   "vless",
				VAllss: &panel.VAllssNode{NetworkSettings: settings},
				Common: &panel.CommonNode{ServerPort: 443},
			}
			option := &conf.Options{ListenIP: "127.0.0.1", XrayOptions: conf.NewXrayOptions()}
			_, err := buildInbound(option, info, "vless-test")
			require.NoError(t, err)
		})
	}
}
