package testutil

import (
	"os"
	"testing"

	"github.com/TBD54566975/ssi-sdk/schema"
	"github.com/stretchr/testify/require"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

func EnableSchemaCaching() {
	s, err := schema.GetAllLocalSchemas()
	if err != nil {
		println(err)
		os.Exit(1)
	}
	l, err := schema.NewCachingLoader(s)
	if err != nil {
		println(err)
		os.Exit(1)
	}
	l.EnableHTTPCache()
}

func TestDB(t *testing.T) storage.ServiceStorage {
	file, err := os.CreateTemp("", "bolt")
	require.NoError(t, err)
	name := file.Name()
	s, err := storage.NewStorage(storage.Bolt, name)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = s.Close()
		_ = file.Close()
		_ = os.Remove(name)
	})
	return s
}
