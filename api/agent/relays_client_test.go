package agent

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/AnixOps/anix-agent/v5/api/agent/agenttest"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

// relayedClient is a client of fake's node whose connections go through
// relays, with target as Control's gRPC target.
func (f *fakeControl) relayedClient(t *testing.T, target string, identity *IdentityConfig, relays ...string) *Client {
	t.Helper()
	dialer, err := NewRelays(relays)
	require.NoError(t, err)
	return f.relayedClientWith(t, target, identity, dialer)
}

func (f *fakeControl) relayedClientWith(t *testing.T, target string, identity *IdentityConfig, dialer *Relays) *Client {
	t.Helper()
	client, err := NewClient(Config{
		Target: target, NodeID: int(f.nodeID), UseTLS: true, ServerName: "control.test",
		RootCAs: f.serverCA, AgentVersion: "test-agent", InstanceID: "instance-1",
		Capabilities: []*agentv1pb.Capability{{Name: "agent.control", Version: "v1"}},
		Heartbeat:    time.Second, ReconnectMin: 10 * time.Millisecond, ReconnectMax: 50 * time.Millisecond,
		DialTimeout: 2 * time.Second, Identity: identity, Relays: dialer,
	})
	require.NoError(t, err)
	return client
}

func (f *fakeControl) handshakeServerNames() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.serverNames...)
}

// closedAddress is a local address nothing listens on.
func closedAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	require.NoError(t, listener.Close())
	return address
}

// Enrollment, the control stream and renewal all go through the relay. The
// target does not resolve, so a direct dial could not succeed; Control sees
// the TLS server name and the client certificate as without a relay.
func TestClientEnrollsStreamsAndRenewsThroughTheRelay(t *testing.T) {
	shortenIdentityRetries(t)
	fake := newFakeControl(t, fakeModeRequired, true)
	fake.setLifetime(3 * time.Second)
	relay := agenttest.StartRelay(t, fake.address)
	root := t.TempDir()
	client := fake.relayedClient(t, "control.invalid:50051", fake.withCredential(t, root, "anixagt_relayed"), relay.Address)
	startClient(t, client)
	waitReady(t, client)
	issued := waitIssued(t, fake, 1)
	fake.setLifetime(time.Hour)

	require.Eventually(t, func() bool {
		_, renews, _, _ := fake.records()
		return len(renews) > 0 && renews[0].err == codes.OK
	}, 10*time.Second, 20*time.Millisecond, "the certificate was not renewed through the relay")

	enrolls, renews, streams, _ := fake.records()
	require.Len(t, enrolls, 1)
	assert.Equal(t, codes.OK, enrolls[0].err)
	assert.Equal(t, issued[0], renews[0].serial, "the renewal presents the enrolled certificate")
	accepted := certificateSessions(streams)
	require.NotEmpty(t, accepted, "no control stream was accepted through the relay")
	assert.Equal(t, issued[0], accepted[0].certificateSerial)

	names := fake.handshakeServerNames()
	require.NotEmpty(t, names)
	for _, name := range names {
		assert.Equal(t, "control.test", name, "every handshake verifies Control's name, not the relay's")
	}
	assert.Positive(t, relay.Carried())
}

// With every relay down, nothing reaches Control, although its address is
// the target and it is listening.
func TestClientNeverDialsControlWhenEveryRelayFails(t *testing.T) {
	shortenIdentityRetries(t)
	fake := newFakeControl(t, fakeModeRequired, true)
	client := fake.relayedClient(t, fake.address, fake.withCredential(t, t.TempDir(), "anixagt_direct"), closedAddress(t))
	startClient(t, client)

	time.Sleep(1500 * time.Millisecond)
	enrolls, renews, streams, _ := fake.records()
	assert.Empty(t, enrolls, "enrolled around the relays")
	assert.Empty(t, renews)
	assert.Empty(t, streams, "opened a stream around the relays")
	assert.Empty(t, fake.handshakeServerNames(), "Control was dialed directly")
	select {
	case <-client.Ready():
		t.Fatal("the client became ready with every relay down")
	default:
	}
}

// A relay that accepts but cannot reach Control is passed over: the other
// relay carries the stream. The broken relay connects faster, so it wins
// the first dial and the client must move off it; a selector that trusted
// the TCP connect would stay on it.
func TestClientMovesOffARelayThatCannotReachControl(t *testing.T) {
	shortenIdentityRetries(t)
	fake := newFakeControl(t, fakeModeRequired, true)
	broken := agenttest.StartRelay(t, fake.address)
	broken.SetBroken(true)
	working := agenttest.StartRelay(t, fake.address)
	dialer, err := NewRelays([]string{broken.Address, working.Address})
	require.NoError(t, err)
	connect := dialer.connect
	dialer.connect = func(ctx context.Context, address string) (net.Conn, time.Duration, error) {
		if address == working.Address {
			time.Sleep(200 * time.Millisecond)
		}
		return connect(ctx, address)
	}
	client := fake.relayedClientWith(t, "control.invalid:50051", fake.withCredential(t, t.TempDir(), "anixagt_failover"), dialer)
	startClient(t, client)

	select {
	case <-client.Ready():
	case <-time.After(15 * time.Second):
		t.Fatal("the client did not move to the working relay")
	}
	dialer.mu.Lock()
	brokenState := dialer.state[0]
	dialer.mu.Unlock()
	assert.Positive(t, brokenState.failures, "the broken relay, which won the first dial, was not counted as failed")
	assert.Positive(t, broken.Accepted())
	assert.Positive(t, working.Carried())
}
