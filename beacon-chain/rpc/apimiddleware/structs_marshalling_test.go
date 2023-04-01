package apimiddleware

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/prysmaticlabs/prysm/v4/testing/assert"
	"github.com/prysmaticlabs/prysm/v4/testing/require"
)

func TestUnmarshalEpochParticipation(t *testing.T) {
	t.Run("valid base64", func(t *testing.T) {
		b := []byte{3, 3, 0}
		b64 := []byte("\"" + base64.StdEncoding.EncodeToString(b) + "\"")
		ep := EpochParticipation{}
		require.NoError(t, ep.UnmarshalJSON(b64))
		require.Equal(t, 3, len(ep))
		assert.Equal(t, "3", ep[0])
		assert.Equal(t, "3", ep[1])
		assert.Equal(t, "0", ep[2])
	})
	t.Run("valid string list", func(t *testing.T) {
		b, err := json.Marshal([]string{"3", "3", "0"})
		require.NoError(t, err)
		ep := EpochParticipation{}
		require.NoError(t, ep.UnmarshalJSON(b))
		require.Equal(t, 3, len(ep))
		assert.Equal(t, "3", ep[0])
		assert.Equal(t, "3", ep[1])
		assert.Equal(t, "0", ep[2])
	})
	t.Run("unsupported list", func(t *testing.T) {
		b, err := json.Marshal([]interface{}{"3", "3", 0})
		require.NoError(t, err)
		ep := EpochParticipation{}
		err = ep.UnmarshalJSON(b)
		require.NotNil(t, err)
		assert.ErrorContains(t, "unsupported epoch participation type `float64` at index `2`", err)
	})
	t.Run("unsupported type", func(t *testing.T) {
		ep := EpochParticipation{}
		err := ep.UnmarshalJSON([]byte("123"))
		require.NotNil(t, err)
		assert.ErrorContains(t, "unsupported epoch participation type", err)
	})
	t.Run("incorrect value", func(t *testing.T) {
		ep := EpochParticipation{}
		err := ep.UnmarshalJSON([]byte(":illegal:"))
		require.NotNil(t, err)
		assert.ErrorContains(t, "failed to unmarshal data `:illegal:`", err)
	})
	t.Run("no quotes", func(t *testing.T) {
		ep := EpochParticipation{}
		err := ep.UnmarshalJSON([]byte("x"))
		require.NotNil(t, err)
		assert.ErrorContains(t, "failed to unmarshal data `x`", err)
	})
	t.Run("null value", func(t *testing.T) {
		ep := EpochParticipation{}
		require.NoError(t, ep.UnmarshalJSON([]byte("null")))
		assert.DeepEqual(t, EpochParticipation([]string{}), ep)
	})
}
