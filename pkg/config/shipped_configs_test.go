package config

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// Shipped sample configs that enable the AS must set as.external_url (the AS JWKS is fetched from
// it at startup) and, when they list CORS headers explicitly, include X-Token-Mode (mandatory on
// /auth/passkey/*; an explicit list replaces the defaults).
func TestShippedConfigs_ASRequirements(t *testing.T) {
	placeholder := regexp.MustCompile(`__SOFTHSM_SLOT_ID__`)
	for _, name := range []string{"config.yaml", "config.production.yaml", "config.pkcs11-softhsm.yaml"} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("..", "..", "configs", name))
			require.NoError(t, err)
			raw = placeholder.ReplaceAll(raw, []byte("0"))
			cfg := defaultConfig()
			require.NoError(t, yaml.Unmarshal(raw, cfg))

			require.True(t, cfg.AS.Enabled, "sample must enable the AS")
			_, err = cfg.AS.ExternalBaseURL()
			assert.NoError(t, err, "as.external_url must be set")
			assert.Contains(t, cfg.Server.CORS.AllowedHeaders, "X-Token-Mode")
		})
	}
}
