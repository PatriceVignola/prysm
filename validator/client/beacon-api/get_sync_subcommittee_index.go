package beacon_api

import (
	"fmt"
	"strconv"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/pkg/errors"
	"github.com/prysmaticlabs/prysm/v3/beacon-chain/rpc/apimiddleware"
	types "github.com/prysmaticlabs/prysm/v3/consensus-types/primitives"
	ethpb "github.com/prysmaticlabs/prysm/v3/proto/prysm/v1alpha1"
)

func (c beaconApiValidatorClient) getSyncSubcommitteeIndex(in *ethpb.SyncSubcommitteeIndexRequest) (*ethpb.SyncSubcommitteeIndexResponse, error) {
	if in == nil {
		return nil, errors.New("sync subcommittee index request is nil")
	}

	encodedPubkey := hexutil.Encode(in.PublicKey)

	// Get the validator index from the pubkey
	stateValidators, err := c.getStateValidators([]string{encodedPubkey}, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get state validator `%s`", encodedPubkey)
	}

	if len(stateValidators.Data) == 0 {
		return nil, errors.Errorf("validator `%s` not found in state", encodedPubkey)
	}

	myValidatorIndex, err := strconv.ParseUint(stateValidators.Data[0].Index, 10, 64)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse validator index `%s`", stateValidators.Data[0].Index)
	}

	jsonSyncCommittees := apimiddleware.SyncCommitteesResponseJson{}
	if _, err := c.jsonRestHandler.GetRestJsonResponse(fmt.Sprintf("/eth/v1/beacon/states/%d/sync_committees", in.Slot), &jsonSyncCommittees); err != nil {
		return nil, errors.Wrap(err, "failed to query GET REST endpoint")
	}

	if jsonSyncCommittees.Data == nil {
		return nil, errors.New("sync committees data is nil")
	}

	var subcommitteeIndices []types.CommitteeIndex

	for subcommitteeIndex, subcommittee := range jsonSyncCommittees.Data.ValidatorAggregates {
		for _, validatorIndexString := range subcommittee {
			validatorIndex, err := strconv.ParseUint(validatorIndexString, 10, 64)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to parse validator index `%s`", validatorIndexString)
			}

			if validatorIndex == myValidatorIndex {
				subcommitteeIndices = append(subcommitteeIndices, types.CommitteeIndex(subcommitteeIndex))
				break
			}
		}
	}

	return &ethpb.SyncSubcommitteeIndexResponse{
		Indices: subcommitteeIndices,
	}, nil
}
