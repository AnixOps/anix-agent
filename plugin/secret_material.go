package plugin

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"syscall"

	"github.com/AnixOps/anix-agent/v4/api/agent"
)

const secretStateFileName = "secret-state.json"

type secretMaterialState struct {
	ConfigHash string   `json:"config_hash"`
	References []string `json:"references"`
}

type preparedSecretConfiguration struct {
	versionDir        string
	runtimeConfig     json.RawMessage
	statePath         string
	stateJSON         []byte
	previousState     []byte
	previousStateSeen bool
	createdPaths      []string
	keepPaths         map[string]struct{}
}

func (s *Supervisor) prepareSecretConfiguration(envelope *agent.OperationEnvelope) (*preparedSecretConfiguration, error) {
	versionDir := s.versionDir(envelope.PluginID, envelope.TargetVersion)
	statePath := filepath.Join(versionDir, "private", secretStateFileName)
	previousState, previousStateSeen, err := readOptionalFile(statePath)
	if err != nil {
		return nil, err
	}
	prepared := &preparedSecretConfiguration{
		versionDir: versionDir, runtimeConfig: append(json.RawMessage(nil), envelope.Config...),
		statePath: statePath, previousState: previousState, previousStateSeen: previousStateSeen,
		keepPaths: make(map[string]struct{}),
	}
	references, err := agent.SecretReferences(envelope.Config)
	if err != nil {
		return nil, err
	}
	state := secretMaterialState{ConfigHash: envelope.ConfigHash, References: make([]string, 0, len(references))}
	for _, reference := range references {
		state.References = append(state.References, reference.String())
	}
	prepared.stateJSON, err = json.Marshal(state)
	if err != nil {
		return nil, err
	}
	if envelope.Version == agent.OperationEnvelopeVersion {
		return prepared, nil
	}

	paths := make(map[string]string, len(envelope.SecretMaterials))
	materials := make(map[string]agent.SecretMaterial, len(envelope.SecretMaterials))
	for _, material := range envelope.SecretMaterials {
		materials[material.Reference] = material
	}
	for _, reference := range references {
		material := materials[reference.String()]
		path := secretMaterialPath(versionDir, reference)
		created, err := writeVerifiedSecretMaterial(path, material)
		if err != nil {
			prepared.rollback()
			return nil, err
		}
		if created {
			prepared.createdPaths = append(prepared.createdPaths, path)
		}
		paths[reference.String()] = path
		prepared.keepPaths[path] = struct{}{}
	}
	prepared.runtimeConfig, err = rewriteSecretReferences(envelope.Config, paths)
	if err != nil {
		prepared.rollback()
		return nil, err
	}
	return prepared, nil
}

func (p *preparedSecretConfiguration) stage() error {
	if p == nil {
		return nil
	}
	return writePrivateFile(p.statePath, p.stateJSON, 0o600)
}

func (p *preparedSecretConfiguration) rollback() error {
	if p == nil {
		return nil
	}
	var result error
	if p.statePath != "" {
		result = errors.Join(result, restoreOptionalFile(p.statePath, p.previousState, p.previousStateSeen))
	}
	for _, path := range p.createdPaths {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			result = errors.Join(result, err)
		}
	}
	return errors.Join(result, removeEmptySecretDirectories(filepath.Join(p.versionDir, "private", "secrets")))
}

func (p *preparedSecretConfiguration) commit() error {
	if p == nil {
		return nil
	}
	return cleanupStaleSecretMaterials(filepath.Join(p.versionDir, "private", "secrets"), p.keepPaths)
}

func secretMaterialPath(versionDir string, reference agent.SecretReference) string {
	return filepath.Join(versionDir, "private", "secrets", reference.SecretID, strconv.FormatUint(reference.Version, 10), reference.Name)
}

func writeVerifiedSecretMaterial(path string, material agent.SecretMaterial) (bool, error) {
	content, err := base64.StdEncoding.DecodeString(material.ContentBase64)
	if err != nil {
		return false, errors.New("decode plugin secret material")
	}
	defer clearBytes(content)
	digest := sha256.Sum256(content)
	if material.SHA256 != hex.EncodeToString(digest[:]) {
		return false, errors.New("plugin secret material digest changed after envelope validation")
	}
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return false, errors.New("existing plugin secret material is not a private regular file")
		}
		existing, err := os.ReadFile(path)
		if err != nil {
			return false, err
		}
		existingDigest := sha256.Sum256(existing)
		clearBytes(existing)
		if material.SHA256 != hex.EncodeToString(existingDigest[:]) {
			return false, errors.New("immutable plugin secret reference conflicts with existing material")
		}
		return false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if err := writePrivateFile(path, content, 0o600); err != nil {
		return false, err
	}
	return true, nil
}

func rewriteSecretReferences(config json.RawMessage, paths map[string]string) (json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(config))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("plugin config must contain one JSON value")
	}
	var rewrite func(any) any
	rewrite = func(current any) any {
		switch typed := current.(type) {
		case map[string]any:
			for key, child := range typed {
				typed[key] = rewrite(child)
			}
			return typed
		case []any:
			for index, child := range typed {
				typed[index] = rewrite(child)
			}
			return typed
		case string:
			if path, ok := paths[typed]; ok {
				return path
			}
		}
		return current
	}
	encoded, err := json.Marshal(rewrite(value))
	if err != nil {
		return nil, err
	}
	return encoded, nil
}

func cleanupStaleSecretMaterials(root string, keep map[string]struct{}) error {
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("plugin secret root must be a real directory")
	}
	var stale []string
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("plugin secret tree must not contain symlinks")
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return errors.New("plugin secret tree contains a non-regular file")
		}
		if _, retained := keep[path]; !retained {
			stale = append(stale, path)
		}
		return nil
	})
	if err != nil {
		return err
	}
	sort.Strings(stale)
	for _, path := range stale {
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	return removeEmptySecretDirectories(root)
}

func removeEmptySecretDirectories(root string) error {
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("plugin secret root must be a real directory")
	}
	var directories []string
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("plugin secret tree must not contain symlinks")
		}
		if entry.IsDir() && path != root {
			directories = append(directories, path)
		}
		return nil
	}); err != nil {
		return err
	}
	sort.Slice(directories, func(i, j int) bool { return len(directories[i]) > len(directories[j]) })
	for _, directory := range directories {
		if err := os.Remove(directory); err != nil && !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, syscall.ENOTEMPTY) && !errors.Is(err, syscall.EEXIST) {
			return err
		}
	}
	if entries, err := os.ReadDir(root); err == nil && len(entries) == 0 {
		return os.Remove(root)
	}
	return nil
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func (p *preparedSecretConfiguration) String() string {
	return fmt.Sprintf("plugin secret configuration (%d retained files)", len(p.keepPaths))
}
