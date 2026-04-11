package vault

import (
	"context"
	"fmt"
	"path"

	vaultapi "github.com/hashicorp/vault/api"
)

// KVVersion represents the KV secrets engine version.
type KVVersion int

const (
	KVv1 KVVersion = 1
	KVv2 KVVersion = 2
)

// KVSecret holds the data and metadata returned from a KV read.
type KVSecret struct {
	Path    string
	Data    map[string]interface{}
	Version int
}

// KVReader reads secrets from a Vault KV secrets engine.
type KVReader struct {
	client  *vaultapi.Client
	version KVVersion
	mount   string
}

// NewKVReader creates a KVReader for the given mount point and KV version.
func NewKVReader(client *vaultapi.Client, mount string, version KVVersion) *KVReader {
	return &KVReader{
		client:  client,
		version: version,
		mount:   mount,
	}
}

// ReadSecret reads a secret at the given relative path under the configured mount.
func (r *KVReader) ReadSecret(ctx context.Context, secretPath string) (*KVSecret, error) {
	if secretPath == "" {
		return nil, fmt.Errorf("kv_reader: secret path must not be empty")
	}

	var apiPath string
	if r.version == KVv2 {
		apiPath = path.Join(r.mount, "data", secretPath)
	} else {
		apiPath = path.Join(r.mount, secretPath)
	}

	secret, err := r.client.Logical().ReadWithContext(ctx, apiPath)
	if err != nil {
		return nil, fmt.Errorf("kv_reader: read %s: %w", apiPath, err)
	}
	if secret == nil {
		return nil, fmt.Errorf("kv_reader: no secret found at %s", apiPath)
	}

	data := secret.Data
	version := 0

	if r.version == KVv2 {
		inner, ok := secret.Data["data"]
		if !ok {
			return nil, fmt.Errorf("kv_reader: kv-v2 response missing 'data' key at %s", apiPath)
		}
		data, ok = inner.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("kv_reader: kv-v2 'data' field has unexpected type at %s", apiPath)
		}
		if meta, ok := secret.Data["metadata"].(map[string]interface{}); ok {
			if v, ok := meta["version"].(float64); ok {
				version = int(v)
			}
		}
	}

	return &KVSecret{
		Path:    secretPath,
		Data:    data,
		Version: version,
	}, nil
}
