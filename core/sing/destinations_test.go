package sing

import (
	"io"
	"net"
	"testing"

	"github.com/AnixOps/anix-agent/v5/common/destinations"
	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDestinationHostPrefersTheSniffedDomain(t *testing.T) {
	assert.Equal(t, "www.youtube.com", destinationHost(adapter.InboundContext{Domain: "www.youtube.com", Destination: M.ParseSocksaddr("1.2.3.4:443")}))
	assert.Equal(t, "example.com", destinationHost(adapter.InboundContext{Destination: M.ParseSocksaddr("example.com:443")}))
	assert.Equal(t, "1.2.3.4", destinationHost(adapter.InboundContext{Destination: M.ParseSocksaddr("1.2.3.4:443")}))
	assert.Empty(t, destinationHost(adapter.InboundContext{}))
}

func TestDestinationConnCountsItsBytesAndReleasesOnce(t *testing.T) {
	collector := destinations.NewCollector()
	client, server := net.Pipe()
	stat := collector.Open("alice", "www.youtube.com", "tls")
	conn := newDestinationConn(server, stat)

	go func() {
		_, _ = client.Write([]byte("hello"))
		_, _ = io.ReadFull(client, make([]byte, 3))
	}()
	buffer := make([]byte, 5)
	_, err := io.ReadFull(conn, buffer)
	require.NoError(t, err)
	_, err = conn.Write([]byte("abc"))
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	require.NoError(t, conn.Close())

	assert.Equal(t, []destinations.Entry{{User: "alice", Domain: "youtube.com", Protocol: "tls", Upload: 5, Download: 3, Connections: 1}}, collector.Snapshot())
	assert.Empty(t, collector.Snapshot(), "released once: the idle destination is dropped")
	assert.Nil(t, collector.Snapshot())
}
