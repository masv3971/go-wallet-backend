package api

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStripSecretSeedAdvertisement(t *testing.T) {
	var md map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(`{"credential_configurations_supported":{
		"a":{"credential_metadata":{"display":[{"name":"A"}],"org.siros.secret_seed":{"namespaces":["x"]}}},
		"b":{"credential_metadata":{"org.siros.secret_seed":{"ns":"deadbeef"}}},
		"c":{"display":[]}, "d":"junk"}}`), &md))
	stripSecretSeedAdvertisement(md)
	out, _ := json.Marshal(md)
	assert.NotContains(t, string(out), "secret_seed")
	assert.NotContains(t, string(out), "deadbeef")
	assert.Contains(t, string(out), `"display":[{"name":"A"}]`)
	stripSecretSeedAdvertisement(map[string]interface{}{}) // no panic
}
