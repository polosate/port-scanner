package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/davesavic/clink"
)

var (
	KVStoreDefaultID string
	DatasetDefaultID string
	KVStoreURL       = "https://api.apify.com/v2/key-value-stores/%s/records/%s?token=%s"
	DatasetURL       = "https://api.apify.com/v2/datasets/%s/items?token=%s"
	Token            string
	xlog             = slog.New(slog.NewTextHandler(os.Stdout, nil))
)

type (
	KVStoreValue map[string]any
	KVStore      struct {
		ID     string
		Client *clink.Client
	}
)

func init() {
	Token = os.Getenv("APIFY_TOKEN")
	KVStoreDefaultID = os.Getenv("APIFY_DEFAULT_KEY_VALUE_STORE_ID")
	DatasetDefaultID = os.Getenv("APIFY_DEFAULT_DATASET_ID")
	if strings.EqualFold(Token, "") || strings.EqualFold(KVStoreDefaultID, "") ||
		strings.EqualFold(DatasetDefaultID, "") {
		xlog.Error("token or default kv store missing")
	}
}

func GetKVStoreEndpoint(id string, key string) string {
	return fmt.Sprintf(KVStoreURL, id, key, Token)
}

func GetDatasetEndpoint(id string) string {
	return fmt.Sprintf(DatasetURL, id, Token)
}

func KVStoreNew(id string) KVStore {
	client := clink.NewClient()
	client.Headers["Content-Type"] = "application/json"
	return KVStore{ID: id, Client: client}
}

func KVStoreDefault() KVStore {
	return KVStoreNew(KVStoreDefaultID)
}

func (kv KVStore) Get(key string) (KVStoreValue, error) {
	url := GetKVStoreEndpoint(kv.ID, key)
	resp, err := kv.Client.Get(url)
	if err != nil {
		xlog.Error("failed to get value", "key", key, "error", err)
		return nil, err
	}
	return KVStoreValueFromResponse(resp), nil
}

func (kv KVStore) Put(key string, payload any) error {
	url := GetKVStoreEndpoint(kv.ID, key)
	_, err := kv.Client.Put(url, KVStoreRequestFrom(payload))
	if err != nil {
		xlog.Error("failed to set value", "key", key, "error", err)
	}
	return err
}

func (kv KVStore) PutToDataset(payload any) error {
	url := GetDatasetEndpoint(DatasetDefaultID)
	_, err := kv.Client.Post(url, KVStoreRequestFrom(payload))
	if err != nil {
		xlog.Error("failed to save items", "error", err)
	}
	return err
}

func KVStoreRequestFrom(v any) io.Reader {
	b, _ := json.Marshal(v)
	return bytes.NewReader(b)
}

func KVStoreValueFromResponse(resp *http.Response) KVStoreValue {
	var value KVStoreValue
	if err := clink.ResponseToJson(resp, &value); err != nil {
		xlog.Error("failed to unmarshal response", "error", err)
	}
	return value
}
