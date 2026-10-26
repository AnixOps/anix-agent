package sing

import (
	"io"
	"net"
	"sync"

	"github.com/AnixOps/anix-agent/v5/common/destinations"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/network"
)

// Destination statistics (destinations.v1): every routed connection of a
// user counts its bytes toward the sniffed domain, or the dialed domain or
// address, through a destinationConn or destinationPacketConn.

// GetDestinationTraffic returns tag's traffic by destination since the last
// call, for the users the core knows.
func (b *Sing) GetDestinationTraffic(tag string) ([]destinations.Traffic, error) {
	entries := b.hookServer.destinations.Snapshot(tag)
	if len(entries) == 0 {
		return nil, nil
	}
	b.users.mapLock.RLock()
	defer b.users.mapLock.RUnlock()
	return destinations.Resolve(entries, func(user string) int { return b.users.uidMap[user] }), nil
}

// destinationHost is the host a connection reached: the sniffed domain,
// else the requested domain or address.
func destinationHost(m adapter.InboundContext) string {
	if m.Domain != "" {
		return m.Domain
	}
	if m.Destination.IsFqdn() {
		return m.Destination.Fqdn
	}
	if m.Destination.Addr.IsValid() {
		return m.Destination.Addr.String()
	}
	return ""
}

type destinationConn struct {
	network.ExtendedConn
	stat    *destinations.Stat
	release sync.Once
}

func newDestinationConn(conn net.Conn, stat *destinations.Stat) net.Conn {
	return &destinationConn{ExtendedConn: bufio.NewExtendedConn(conn), stat: stat}
}

func (c *destinationConn) Read(b []byte) (n int, err error) {
	n, err = c.ExtendedConn.Read(b)
	c.stat.Upload.Add(int64(n))
	return
}

func (c *destinationConn) Write(b []byte) (n int, err error) {
	n, err = c.ExtendedConn.Write(b)
	c.stat.Download.Add(int64(n))
	return
}

func (c *destinationConn) ReadBuffer(buffer *buf.Buffer) error {
	err := c.ExtendedConn.ReadBuffer(buffer)
	if err != nil {
		return err
	}
	c.stat.Upload.Add(int64(buffer.Len()))
	return nil
}

func (c *destinationConn) WriteBuffer(buffer *buf.Buffer) error {
	n := int64(buffer.Len())
	if err := c.ExtendedConn.WriteBuffer(buffer); err != nil {
		return err
	}
	c.stat.Download.Add(n)
	return nil
}

func (c *destinationConn) UnwrapReader() (io.Reader, []network.CountFunc) {
	return c.ExtendedConn, []network.CountFunc{func(n int64) { c.stat.Upload.Add(n) }}
}

func (c *destinationConn) UnwrapWriter() (io.Writer, []network.CountFunc) {
	return c.ExtendedConn, []network.CountFunc{func(n int64) { c.stat.Download.Add(n) }}
}

func (c *destinationConn) Upstream() any {
	return c.ExtendedConn
}

func (c *destinationConn) Close() error {
	c.release.Do(c.stat.Release)
	return c.ExtendedConn.Close()
}

type destinationPacketConn struct {
	network.PacketConn
	stat    *destinations.Stat
	release sync.Once
}

func newDestinationPacketConn(conn network.PacketConn, stat *destinations.Stat) network.PacketConn {
	return &destinationPacketConn{PacketConn: conn, stat: stat}
}

func (p *destinationPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	destination, err = p.PacketConn.ReadPacket(buffer)
	if err != nil {
		return
	}
	p.stat.Upload.Add(int64(buffer.Len()))
	return
}

func (p *destinationPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	n := int64(buffer.Len())
	if err := p.PacketConn.WritePacket(buffer, destination); err != nil {
		return err
	}
	p.stat.Download.Add(n)
	return nil
}

func (p *destinationPacketConn) UnwrapPacketReader() (network.PacketReader, []network.CountFunc) {
	return p.PacketConn, []network.CountFunc{func(n int64) { p.stat.Upload.Add(n) }}
}

func (p *destinationPacketConn) UnwrapPacketWriter() (network.PacketWriter, []network.CountFunc) {
	return p.PacketConn, []network.CountFunc{func(n int64) { p.stat.Download.Add(n) }}
}

func (p *destinationPacketConn) Upstream() any {
	return p.PacketConn
}

func (p *destinationPacketConn) Close() error {
	p.release.Do(p.stat.Release)
	return p.PacketConn.Close()
}
