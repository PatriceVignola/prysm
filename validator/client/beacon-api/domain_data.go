//go:build use_beacon_api
// +build use_beacon_api

package beacon_api

import (
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/pkg/errors"
	ethpb "github.com/prysmaticlabs/prysm/v3/proto/prysm/v1alpha1"
)

func (c beaconApiValidatorClient) getDomainData(domainType []byte) (*ethpb.DomainResponse, error) {
	// 1. Get genesis_fork_version and genesis_validators_root from the Genesis call
	genesis, err := c.getGenesis()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get genesis info")
	}

	if !validForkVersion(genesis.Data.GenesisForkVersion) {
		return nil, errors.Errorf("invalid genesis fork version: %s", genesis.Data.GenesisForkVersion)
	}

	forkVersion, err := hexutil.Decode(genesis.Data.GenesisForkVersion)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode genesis fork version")
	}

	if !validRoot(genesis.Data.GenesisValidatorsRoot) {
		return nil, errors.Errorf("invalid genesis validators root: %s", genesis.Data.GenesisValidatorsRoot)
	}

	genesisValidatorRoot, err := hexutil.Decode(genesis.Data.GenesisValidatorsRoot)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode genesis validators root")
	}

	// 2. Compute hash_tree_root of genesis_fork_version and genesis_validators_root
	forkDataRoot, err := (&ethpb.ForkData{
		CurrentVersion:        forkVersion,
		GenesisValidatorsRoot: genesisValidatorRoot,
	}).HashTreeRoot()
	if err != nil {
		return nil, errors.Wrap(err, "failed to hash the fork data")
	}

	// 3. Append the last 28 bytes of the fork data root to the domain type
	if len(domainType) != 4 {
		return nil, errors.Errorf("invalid domain type: %s", string(domainType))
	}

	signatureDomain := make([]byte, 0, 32)
	signatureDomain = append(signatureDomain, domainType...)
	signatureDomain = append(signatureDomain, forkDataRoot[:28]...)

	return &ethpb.DomainResponse{SignatureDomain: signatureDomain}, nil
}
