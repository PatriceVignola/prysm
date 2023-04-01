package apimiddleware

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strconv"

	"github.com/pkg/errors"
)

// EpochParticipation represents participation of validators in their duties.
type EpochParticipation []string

func (p *EpochParticipation) UnmarshalJSON(b []byte) error {
	var rawData interface{}
	if err := json.Unmarshal(b, &rawData); err != nil {
		return errors.Wrapf(err, "failed to unmarshal data `%s`", b)
	}

	switch unmarshaledData := rawData.(type) {
	case string:
		decoded, err := base64.StdEncoding.DecodeString(unmarshaledData)
		if err != nil {
			return errors.Wrapf(err, "could not decode epoch participation base64 value")
		}

		*p = make([]string, len(decoded))
		for i, participation := range decoded {
			(*p)[i] = strconv.FormatUint(uint64(participation), 10)
		}
	case []interface{}:
		// If we already have an array of strings, just return it as-is
		*p = make([]string, len(unmarshaledData))
		for i, participation := range unmarshaledData {
			switch unmarshaledParticipation := participation.(type) {
			case string:
				(*p)[i] = unmarshaledParticipation
			default:
				return errors.Errorf("unsupported epoch participation type `%s` at index `%d`", reflect.TypeOf(unmarshaledParticipation), i)
			}
		}
	case nil:
		return nil
	default:
		return errors.Errorf("unsupported epoch participation type `%s`", reflect.TypeOf(unmarshaledData))
	}

	return nil
}
