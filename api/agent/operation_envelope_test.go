package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	agentv1pb "github.com/AnixOps/anix-agent/v4/api/grpc/agent/v1"
	"github.com/stretchr/testify/require"
)

func TestDecodeOperationEnvelopeRejectsOversizedPayload(t *testing.T) {
	operation := &agentv1pb.DesiredOperation{
		OperationId: "oversized-operation", Revision: 1,
		PayloadJson: bytes.Repeat([]byte("x"), maxOperationEnvelopeBytes+1),
	}
	_, err := DecodeOperationEnvelope(operation)
	require.ErrorContains(t, err, "size limit")
}

func TestDecodeOperationEnvelopeV2ValidatesExactSecretMaterialSet(t *testing.T) {
	config := []byte(`{"tls":{"ca_file":"secret://mesh-edge@1/ca.pem","key_file":"secret://mesh-edge@1/client.key"}}`)
	configDigest := sha256.Sum256(config)
	material := func(reference, content string) SecretMaterial {
		digest := sha256.Sum256([]byte(content))
		return SecretMaterial{Reference: reference, SHA256: hex.EncodeToString(digest[:]), ContentBase64: base64.StdEncoding.EncodeToString([]byte(content))}
	}
	envelope := OperationEnvelope{
		Version: OperationEnvelopeVersionV2, OperationID: "operation-v2", IdempotencyKey: "operation-v2-key",
		SessionID: "session-v2", Revision: 4, PluginID: "gost-mesh", TargetVersion: "1.0.0",
		ConfigHash: hex.EncodeToString(configDigest[:]), Config: config,
		SecretMaterials: []SecretMaterial{
			material("secret://mesh-edge@1/ca.pem", "ca"),
			material("secret://mesh-edge@1/client.key", "key"),
		},
	}
	payload, err := json.Marshal(envelope)
	require.NoError(t, err)
	operation := &agentv1pb.DesiredOperation{OperationId: envelope.OperationID, Revision: envelope.Revision, PayloadJson: payload}
	decoded, err := DecodeOperationEnvelope(operation)
	require.NoError(t, err)
	require.Equal(t, envelope.SecretMaterials, decoded.SecretMaterials)

	missing := envelope
	missing.SecretMaterials = missing.SecretMaterials[:1]
	payload, err = json.Marshal(missing)
	require.NoError(t, err)
	operation.PayloadJson = payload
	_, err = DecodeOperationEnvelope(operation)
	require.ErrorContains(t, err, "does not match config references")

	tampered := envelope
	tampered.SecretMaterials = append([]SecretMaterial(nil), envelope.SecretMaterials...)
	tampered.SecretMaterials[0].ContentBase64 = base64.StdEncoding.EncodeToString([]byte("different"))
	payload, err = json.Marshal(tampered)
	require.NoError(t, err)
	operation.PayloadJson = payload
	_, err = DecodeOperationEnvelope(operation)
	require.ErrorContains(t, err, "sha256 does not match")

	legacy := envelope
	legacy.Version = OperationEnvelopeVersion
	payload, err = json.Marshal(legacy)
	require.NoError(t, err)
	operation.PayloadJson = payload
	_, err = DecodeOperationEnvelope(operation)
	require.ErrorContains(t, err, "v1 cannot carry")
}

func readAgentOperationEnvelopeGolden(t *testing.T) []byte {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	require.True(t, ok)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "..", "..", "contracts", "agent", "v1", "operation-envelope-golden.json"))
	require.NoError(t, err)
	return bytes.TrimSpace(raw)
}

func TestDecodeOperationEnvelopeMatchesControlGolden(t *testing.T) {
	operation := &agentv1pb.DesiredOperation{
		OperationId: "6d1e2a5b-2f43-41a7-a4d3-19f3f93f8c3a",
		Revision:    7,
		PayloadJson: readAgentOperationEnvelopeGolden(t),
	}

	envelope, err := DecodeOperationEnvelopeContext(withOperationSession(context.Background(), "agent-session-golden"), operation)
	require.NoError(t, err)
	require.Equal(t, OperationEnvelopeVersion, envelope.Version)
	require.Equal(t, "wireguard", envelope.PluginID)
	require.Equal(t, "1.0.0", envelope.TargetVersion)
	require.JSONEq(t, `{"endpoint":"edge.example","listen_port":51820,"private_key_ref":"secret/wg-42"}`, string(envelope.Config))

	encoded, err := json.Marshal(envelope)
	require.NoError(t, err)
	require.Equal(t, string(readAgentOperationEnvelopeGolden(t)), string(encoded))
}

func TestDecodeOperationEnvelopeValidatesOuterFieldsAndConfigHash(t *testing.T) {
	config := []byte(`{"secret_ref":"secret/wireguard-entry","mtu":1420}`)
	digest := sha256.Sum256(config)
	operation := &agentv1pb.DesiredOperation{OperationId: "operation-1", Revision: 9}
	operation.PayloadJson = []byte(`{"version":"anixops.operation/v1","operation_id":"operation-1","idempotency_key":"node-1-9","session_id":"session-1","revision":9,"plugin_id":"wireguard","target_version":"1.0.0","config_hash":"` + hex.EncodeToString(digest[:]) + `","config":` + string(config) + `}`)

	envelope, err := DecodeOperationEnvelope(operation)
	require.NoError(t, err)
	require.Equal(t, "wireguard", envelope.PluginID)

	operation.PayloadJson = []byte(`{"version":"anixops.operation/v1","operation_id":"other","idempotency_key":"node-1-9","session_id":"session-1","revision":9,"plugin_id":"wireguard","target_version":"1.0.0","config_hash":"` + hex.EncodeToString(digest[:]) + `","config":` + string(config) + `}`)
	_, err = DecodeOperationEnvelope(operation)
	require.ErrorContains(t, err, "operation_id")
}

func TestDecodeOperationEnvelopeKeepsLegacyPayloadCompatible(t *testing.T) {
	operation := &agentv1pb.DesiredOperation{OperationId: "legacy", Revision: 1, PayloadJson: []byte(`{"message":"ping"}`)}
	_, err := DecodeOperationEnvelope(operation)
	require.ErrorIs(t, err, ErrNotPluginEnvelope)
	_, err = DecodeOperationEnvelopeContext(withOperationSession(context.Background(), "session-1"), operation)
	require.ErrorIs(t, err, ErrNotPluginEnvelope)
}

func TestDecodeOperationEnvelopeRejectsUnsafePathAndUnboundEmptyConfig(t *testing.T) {
	emptyHash := sha256.Sum256(nil)
	operation := &agentv1pb.DesiredOperation{OperationId: "operation-2", Revision: 2}
	operation.PayloadJson = []byte(`{"version":"anixops.operation/v1","operation_id":"operation-2","idempotency_key":"node-1-2","session_id":"session-1","revision":2,"plugin_id":"../wireguard","target_version":"1.0.0","config_hash":"` + hex.EncodeToString(emptyHash[:]) + `"}`)
	_, err := DecodeOperationEnvelope(operation)
	require.ErrorContains(t, err, "required fields")

	operation.PayloadJson = []byte(`{"version":"anixops.operation/v1","operation_id":"operation-2","idempotency_key":"node-1-2","session_id":"session-1","revision":2,"plugin_id":"wireguard","target_version":"1.0.0","config_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
	_, err = DecodeOperationEnvelope(operation)
	require.ErrorContains(t, err, "does not match config")
}

func TestDecodeOperationEnvelopeContextBindsActiveSession(t *testing.T) {
	config := []byte(`{}`)
	digest := sha256.Sum256(config)
	operation := &agentv1pb.DesiredOperation{OperationId: "operation-session", Revision: 3}
	operation.PayloadJson = []byte(`{"version":"anixops.operation/v1","operation_id":"operation-session","idempotency_key":"node-1-3","session_id":"active-session","revision":3,"plugin_id":"wireguard","target_version":"1.0.0","config_hash":"` + hex.EncodeToString(digest[:]) + `","config":{}}`)

	envelope, err := DecodeOperationEnvelopeContext(withOperationSession(context.Background(), "active-session"), operation)
	require.NoError(t, err)
	require.Equal(t, "active-session", envelope.SessionID)

	_, err = DecodeOperationEnvelopeContext(withOperationSession(context.Background(), "replaced-session"), operation)
	require.ErrorContains(t, err, "does not match active")
	_, err = DecodeOperationEnvelopeContext(context.Background(), operation)
	require.ErrorContains(t, err, "unavailable")
}
