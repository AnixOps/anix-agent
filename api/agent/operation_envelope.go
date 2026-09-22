package agent

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	agentv1pb "github.com/AnixOps/anix-agent/v4/api/grpc/agent/v1"
)

const (
	OperationEnvelopeVersion   = "anixops.operation/v1"
	OperationEnvelopeVersionV2 = "anixops.operation/v2"
	maxSecretMaterials         = 16
	maxSecretMaterialBytes     = 1 << 20
	maxSecretMaterialTotal     = 4 << 20
	maxOperationEnvelopeBytes  = 6 << 20
)

var ErrNotPluginEnvelope = errors.New("desired operation is not an AnixOps plugin envelope")

type operationSessionContextKey struct{}

// OperationEnvelope travels in DesiredOperation.payload_json. Keeping the
// outer protobuf stable lets older Agents retain their compatibility commands
// while plugin-aware Agents can require the full persistent-operation contract.
type OperationEnvelope struct {
	Version         string           `json:"version"`
	OperationID     string           `json:"operation_id"`
	IdempotencyKey  string           `json:"idempotency_key"`
	SessionID       string           `json:"session_id"`
	Revision        uint64           `json:"revision"`
	PluginID        string           `json:"plugin_id"`
	TargetVersion   string           `json:"target_version"`
	ConfigHash      string           `json:"config_hash"`
	Config          json.RawMessage  `json:"config"`
	SecretMaterials []SecretMaterial `json:"secret_materials,omitempty"`
}

type SecretMaterial struct {
	Reference     string `json:"reference"`
	SHA256        string `json:"sha256"`
	ContentBase64 string `json:"content_base64"`
}

type SecretReference struct {
	SecretID string
	Version  uint64
	Name     string
}

func (r SecretReference) String() string {
	return fmt.Sprintf("secret://%s@%d/%s", r.SecretID, r.Version, r.Name)
}

func DecodeOperationEnvelope(operation *agentv1pb.DesiredOperation) (*OperationEnvelope, error) {
	if operation == nil || len(operation.PayloadJson) == 0 {
		return nil, ErrNotPluginEnvelope
	}
	if len(operation.PayloadJson) > maxOperationEnvelopeBytes {
		return nil, errors.New("plugin operation envelope exceeds size limit")
	}
	var probe struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(operation.PayloadJson, &probe); err != nil {
		return nil, fmt.Errorf("decode desired operation payload: %w", err)
	}
	if probe.Version == "" {
		return nil, ErrNotPluginEnvelope
	}
	var envelope OperationEnvelope
	decoder := json.NewDecoder(strings.NewReader(string(operation.PayloadJson)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return nil, fmt.Errorf("decode plugin operation envelope: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, errors.New("decode plugin operation envelope: multiple JSON values")
	}
	if err := envelope.Validate(operation); err != nil {
		return nil, err
	}
	return &envelope, nil
}

// DecodeOperationEnvelopeContext additionally binds a plugin operation to the
// active Agent Control stream. DecodeOperationEnvelope remains available for
// offline validation and legacy callers that do not own a live session.
func DecodeOperationEnvelopeContext(ctx context.Context, operation *agentv1pb.DesiredOperation) (*OperationEnvelope, error) {
	envelope, err := DecodeOperationEnvelope(operation)
	if err != nil {
		return nil, err
	}
	activeSession, ok := operationSessionFromContext(ctx)
	if !ok {
		return nil, errors.New("active agent control session is unavailable")
	}
	if envelope.SessionID != activeSession {
		return nil, errors.New("plugin operation session_id does not match active agent control session")
	}
	return envelope, nil
}

func withOperationSession(ctx context.Context, sessionID string) context.Context {
	return context.WithValue(ctx, operationSessionContextKey{}, sessionID)
}

func operationSessionFromContext(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	sessionID, ok := ctx.Value(operationSessionContextKey{}).(string)
	return sessionID, ok && validIdentity(sessionID, 160)
}

func (e OperationEnvelope) Validate(operation *agentv1pb.DesiredOperation) error {
	if e.Version != OperationEnvelopeVersion && e.Version != OperationEnvelopeVersionV2 {
		return fmt.Errorf("unsupported operation envelope version %q", e.Version)
	}
	if operation == nil || !validIdentity(e.OperationID, 160) || e.OperationID != operation.OperationId {
		return errors.New("operation_id does not match desired operation")
	}
	if !validIdentity(e.IdempotencyKey, 160) || !validIdentity(e.SessionID, 160) || !validPathSegment(e.PluginID) || !validPathSegment(e.TargetVersion) {
		return errors.New("plugin operation envelope is missing required fields")
	}
	if e.Revision == 0 || e.Revision != operation.Revision {
		return errors.New("plugin operation revision does not match desired operation")
	}
	if len(e.ConfigHash) != sha256.Size*2 {
		return errors.New("plugin operation config_hash must be a SHA-256 digest")
	}
	if _, err := hex.DecodeString(e.ConfigHash); err != nil {
		return errors.New("plugin operation config_hash must be hexadecimal")
	}
	if len(e.Config) > 0 && !json.Valid(e.Config) {
		return errors.New("plugin operation config must be valid JSON")
	}
	digest := sha256.Sum256(e.Config)
	if !strings.EqualFold(e.ConfigHash, hex.EncodeToString(digest[:])) {
		return errors.New("plugin operation config_hash does not match config")
	}
	if err := e.ValidateSecretMaterials(); err != nil {
		return err
	}
	return nil
}

func (e OperationEnvelope) ValidateSecretMaterials() error {
	references, err := SecretReferences(e.Config)
	if err != nil {
		return err
	}
	if e.Version == OperationEnvelopeVersion {
		if len(e.SecretMaterials) != 0 || len(references) != 0 {
			return errors.New("operation envelope v1 cannot carry plugin secret references or material")
		}
		return nil
	}
	if len(references) == 0 || len(e.SecretMaterials) != len(references) || len(e.SecretMaterials) > maxSecretMaterials {
		return errors.New("operation envelope v2 secret material set does not match config references")
	}
	byReference := make(map[string]SecretMaterial, len(e.SecretMaterials))
	total := 0
	for _, material := range e.SecretMaterials {
		reference, err := ParseSecretReference(material.Reference)
		if err != nil {
			return err
		}
		canonical := reference.String()
		if _, duplicate := byReference[canonical]; duplicate {
			return errors.New("operation envelope contains duplicate plugin secret material")
		}
		if len(material.SHA256) != sha256.Size*2 || material.SHA256 != strings.ToLower(material.SHA256) {
			return errors.New("plugin secret material sha256 must be lowercase hexadecimal")
		}
		if _, err := hex.DecodeString(material.SHA256); err != nil {
			return errors.New("plugin secret material sha256 must be lowercase hexadecimal")
		}
		content, err := base64.StdEncoding.DecodeString(material.ContentBase64)
		if err != nil || base64.StdEncoding.EncodeToString(content) != material.ContentBase64 {
			return errors.New("plugin secret material content must use canonical base64")
		}
		if len(content) == 0 || len(content) > maxSecretMaterialBytes {
			return errors.New("plugin secret material size is invalid")
		}
		total += len(content)
		if total > maxSecretMaterialTotal {
			return errors.New("plugin secret material total size is invalid")
		}
		digest := sha256.Sum256(content)
		if material.SHA256 != hex.EncodeToString(digest[:]) {
			return errors.New("plugin secret material sha256 does not match content")
		}
		byReference[canonical] = material
	}
	for _, reference := range references {
		if _, ok := byReference[reference.String()]; !ok {
			return errors.New("operation envelope is missing plugin secret material")
		}
	}
	return nil
}

func SecretReferences(config json.RawMessage) ([]SecretReference, error) {
	if len(strings.TrimSpace(string(config))) == 0 {
		return nil, nil
	}
	decoder := json.NewDecoder(strings.NewReader(string(config)))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("decode plugin config for secret references: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("plugin config must contain one JSON value")
	}
	unique := make(map[string]SecretReference)
	var walk func(any) error
	walk = func(current any) error {
		switch typed := current.(type) {
		case map[string]any:
			for _, child := range typed {
				if err := walk(child); err != nil {
					return err
				}
			}
		case []any:
			for _, child := range typed {
				if err := walk(child); err != nil {
					return err
				}
			}
		case string:
			if !strings.HasPrefix(typed, "secret://") {
				return nil
			}
			reference, err := ParseSecretReference(typed)
			if err != nil {
				return err
			}
			unique[reference.String()] = reference
		}
		return nil
	}
	if err := walk(value); err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(unique))
	for key := range unique {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]SecretReference, 0, len(keys))
	for _, key := range keys {
		result = append(result, unique[key])
	}
	return result, nil
}

func ParseSecretReference(raw string) (SecretReference, error) {
	if raw != strings.TrimSpace(raw) || !strings.HasPrefix(raw, "secret://") {
		return SecretReference{}, errors.New("plugin secret reference is invalid")
	}
	identity, name, found := strings.Cut(strings.TrimPrefix(raw, "secret://"), "/")
	secretID, versionText, versionFound := strings.Cut(identity, "@")
	if !found || !versionFound || strings.Contains(name, "/") || strings.Contains(versionText, "@") ||
		!validSecretSegment(secretID, 120) || !validSecretFileName(name) {
		return SecretReference{}, errors.New("plugin secret reference must be secret://id@version/file")
	}
	version, err := strconv.ParseUint(versionText, 10, 64)
	if err != nil || version == 0 || strconv.FormatUint(version, 10) != versionText {
		return SecretReference{}, errors.New("plugin secret reference version is invalid")
	}
	reference := SecretReference{SecretID: secretID, Version: version, Name: name}
	if reference.String() != raw {
		return SecretReference{}, errors.New("plugin secret reference is not canonical")
	}
	return reference, nil
}

func validSecretSegment(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum || value != strings.ToLower(value) || value == "." || value == ".." || strings.Contains(value, "..") {
		return false
	}
	for index := range value {
		char := value[index]
		if char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '.' || char == '_' || char == '-' {
			continue
		}
		return false
	}
	first, last := value[0], value[len(value)-1]
	return (first >= 'a' && first <= 'z' || first >= '0' && first <= '9') &&
		(last >= 'a' && last <= 'z' || last >= '0' && last <= '9')
}

func validSecretFileName(value string) bool {
	if len(value) == 0 || len(value) > 120 || value == "." || value == ".." || strings.ContainsAny(value, "/\\\x00\r\n") {
		return false
	}
	for index := range value {
		char := value[index]
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '.' || char == '_' || char == '-' {
			continue
		}
		return false
	}
	return true
}

func validIdentity(value string, maxLength int) bool {
	return value != "" && len(value) <= maxLength && value == strings.TrimSpace(value) && !strings.ContainsAny(value, "\x00\r\n")
}

func validPathSegment(value string) bool {
	if !validIdentity(value, 120) || value == "." || value == ".." || strings.ContainsAny(value, `\\/`) {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || strings.ContainsRune("._+-", char) {
			continue
		}
		return false
	}
	return true
}
