package beacon_api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/pkg/errors"
	"github.com/prysmaticlabs/prysm/v4/beacon-chain/core/altair"
	"github.com/prysmaticlabs/prysm/v4/beacon-chain/rpc/apimiddleware"
	"github.com/prysmaticlabs/prysm/v4/config/params"
	"github.com/prysmaticlabs/prysm/v4/consensus-types/primitives"
	ethpb "github.com/prysmaticlabs/prysm/v4/proto/prysm/v1alpha1"
	"github.com/prysmaticlabs/prysm/v4/validator/client/iface"
)

type beaconApiBeaconChainClient struct {
	fallbackClient          iface.BeaconChainClient
	jsonRestHandler         jsonRestHandler
	stateValidatorsProvider stateValidatorsProvider
}

func (c beaconApiBeaconChainClient) GetChainHead(ctx context.Context, in *empty.Empty) (*ethpb.ChainHead, error) {
	if c.fallbackClient != nil {
		return c.fallbackClient.GetChainHead(ctx, in)
	}

	// TODO: Implement me
	panic("beaconApiBeaconChainClient.GetChainHead is not implemented. To use a fallback client, pass a fallback client as the last argument of NewBeaconApiBeaconChainClientWithFallback.")
}

func (c beaconApiBeaconChainClient) ListValidatorBalances(ctx context.Context, in *ethpb.ListValidatorBalancesRequest) (*ethpb.ValidatorBalances, error) {
	if c.fallbackClient != nil {
		return c.fallbackClient.ListValidatorBalances(ctx, in)
	}

	// TODO: Implement me
	panic("beaconApiBeaconChainClient.ListValidatorBalances is not implemented. To use a fallback client, pass a fallback client as the last argument of NewBeaconApiBeaconChainClientWithFallback.")
}

func (c beaconApiBeaconChainClient) ListValidators(ctx context.Context, in *ethpb.ListValidatorsRequest) (*ethpb.Validators, error) {
	if c.fallbackClient != nil {
		return c.fallbackClient.ListValidators(ctx, in)
	}

	// TODO: Implement me
	panic("beaconApiBeaconChainClient.ListValidators is not implemented. To use a fallback client, pass a fallback client as the last argument of NewBeaconApiBeaconChainClientWithFallback.")
}

func (c beaconApiBeaconChainClient) GetValidatorQueue(ctx context.Context, in *empty.Empty) (*ethpb.ValidatorQueue, error) {
	if c.fallbackClient != nil {
		return c.fallbackClient.GetValidatorQueue(ctx, in)
	}

	// TODO: Implement me
	panic("beaconApiBeaconChainClient.GetValidatorQueue is not implemented. To use a fallback client, pass a fallback client as the last argument of NewBeaconApiBeaconChainClientWithFallback.")
}

func (c beaconApiBeaconChainClient) GetValidatorPerformance(ctx context.Context, in *ethpb.ValidatorPerformanceRequest) (*ethpb.ValidatorPerformanceResponse, error) {
	if in.PublicKeys == nil {
		return nil, errors.New("no public keys found")
	}

	const beaconStateEndpoint = "/eth/v2/debug/beacon/states/head"

	type abstractBeaconStateJson struct {
		Version             string          `json:"version" enum:"true"`
		ExecutionOptimistic bool            `json:"execution_optimistic"`
		Data                json.RawMessage `json:"data"`
	}

	// Since we don't know yet what the json looks like, we unmarshal into an abstract structure that has only a version
	// and a blob of data
	beaconStateJson := abstractBeaconStateJson{}
	if _, err := c.jsonRestHandler.GetRestJsonResponse(ctx, beaconStateEndpoint, &beaconStateJson); err != nil {
		return nil, errors.Wrapf(err, "failed to query REST endpoint `%s` (GET)", beaconStateEndpoint)
	}

	// Once we know what the consensus version is, we can go ahead and unmarshal into the specific structs unique to each version
	decoder := json.NewDecoder(bytes.NewReader(beaconStateJson.Data))
	decoder.DisallowUnknownFields()

	pubkeys := make([]string, len(in.PublicKeys))
	for idx, pubkeyBytes := range in.PublicKeys {
		pubkeys[idx] = hexutil.Encode(pubkeyBytes)
	}

	stateValidatorsResponse, err := c.stateValidatorsProvider.GetStateValidators(ctx, pubkeys, nil, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get head state validators for indices `%v`", in.PublicKeys)
	}

	cfg := params.BeaconConfig()
	targetIdx := cfg.TimelyTargetFlagIndex
	sourceIdx := cfg.TimelySourceFlagIndex
	headIdx := cfg.TimelyHeadFlagIndex

	var activeValidatorBalanceSum uint64
	var activeValidatorCount uint64
	currentEffectiveBalances := make([]uint64, len(pubkeys))

	validatorPubkeyToIndex := make(map[string]primitives.ValidatorIndex, len(pubkeys))

	for idx, stateValidator := range stateValidatorsResponse.Data {
		if stateValidator == nil || stateValidator.Validator == nil {
			return nil, errors.New("state validator is nil")
		}

		currentEffectiveBalance, err := strconv.ParseUint(stateValidator.Validator.EffectiveBalance, 10, 64)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse validator effective balance `%s`", stateValidator.Validator.EffectiveBalance)
		}

		currentEffectiveBalances[idx] = currentEffectiveBalance

		balance, err := strconv.ParseUint(stateValidator.Balance, 10, 64)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse balance `%s` for validator index `%s`", stateValidator.Balance, stateValidator.Index)
		}

		if strings.HasPrefix(stateValidator.Status, "active_") {
			activeValidatorBalanceSum += balance
			activeValidatorCount++
		}

		validatorIndex, err := strconv.ParseUint(stateValidator.Index, 10, 64)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse state validator index `%s`", stateValidator.Index)
		}

		validatorPubkeyToIndex[stateValidator.Validator.PublicKey] = primitives.ValidatorIndex(validatorIndex)
	}

	correctlyVotedSource := make([]bool, len(pubkeys))
	correctlyVotedTarget := make([]bool, len(pubkeys))
	correctlyVotedHead := make([]bool, len(pubkeys))
	balancesBeforeEpochTransition := make([]uint64, len(pubkeys))

	// Spec code:
	// def translate_participation(state: BeaconState, pending_attestations: Sequence[phase0.PendingAttestation]) -> None:
	//
	//	for attestation in pending_attestations:
	//	    data = attestation.data
	//	    inclusion_delay = attestation.inclusion_delay
	//	    # Translate attestation inclusion info to flag indices
	//	    participation_flag_indices = get_attestation_participation_flag_indices(state, data, inclusion_delay)
	//
	//	    # Apply flags to all attesting validators
	//	    epoch_participation = state.previous_epoch_participation
	//	    for index in get_attesting_indices(state, data, attestation.aggregation_bits):
	//	        for flag_index in participation_flag_indices:
	//	            epoch_participation[index] = add_flag(epoch_participation[index], flag_index)

	// def get_attestation_participation_flag_indices(state: BeaconState, data: AttestationData, inclusion_delay: uint64) -> Sequence[int]:
	//     """
	//     Return the flag indices that are satisfied by an attestation.
	//     """
	//     if data.target.epoch == get_current_epoch(state):
	//     justified_checkpoint = state.current_justified_checkpoint
	//     else:
	//     justified_checkpoint = state.previous_justified_checkpoint
	//
	//     # Matching roots
	//     is_matching_source = data.source == justified_checkpoint
	//     is_matching_target = is_matching_source and data.target.root == get_block_root(state, data.target.epoch)
	//     is_matching_head = is_matching_target and data.beacon_block_root == get_block_root_at_slot(state, data.slot)
	//     assert is_matching_source
	//
	//     participation_flag_indices = []
	//     if is_matching_source and inclusion_delay <= integer_squareroot(SLOTS_PER_EPOCH):
	//     participation_flag_indices.append(TIMELY_SOURCE_FLAG_INDEX)
	//     if is_matching_target and inclusion_delay <= SLOTS_PER_EPOCH:
	//     participation_flag_indices.append(TIMELY_TARGET_FLAG_INDEX)
	//     if is_matching_head and inclusion_delay == MIN_ATTESTATION_INCLUSION_DELAY:
	//     participation_flag_indices.append(TIMELY_HEAD_FLAG_INDEX)
	//
	//     return participation_flag_indices

	switch beaconStateJson.Version {
	case "phase0":
		phase0BeaconState := apimiddleware.BeaconStateJson{}
		if err := decoder.Decode(&phase0BeaconState); err != nil {
			return nil, errors.Wrap(err, "failed to decode phase0 beacon state response json")
		}
	case "altair":
		altairBeaconState := apimiddleware.BeaconStateAltairJson{}
		if err := decoder.Decode(&altairBeaconState); err != nil {
			return nil, errors.Wrap(err, "failed to decode altair beacon state response json")
		}

		for idx, validatorPubKey := range pubkeys {
			validatorIndex, ok := validatorPubkeyToIndex[validatorPubKey]
			if !ok {
				return nil, errors.Errorf("failed to get index for validator `%s`", validatorPubKey)
			}

			if uint64(validatorIndex) >= uint64(len(altairBeaconState.PreviousEpochParticipation)) {
				return nil, errors.Errorf("validator index `%d` is too big for length `%d` of the current epoch participations", validatorIndex, len(altairBeaconState.CurrentEpochParticipation))
			}

			previousEpochParticipationString := altairBeaconState.PreviousEpochParticipation[validatorIndex]
			log.Errorf("*******************previousEpochParticipationString: %s", previousEpochParticipationString)
			previousEpochParticipation, err := strconv.ParseUint(previousEpochParticipationString, 10, 8)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to parse current epoch participation `%s`", previousEpochParticipationString)
			}

			previousEpochParticipationByte := byte(previousEpochParticipation)

			hasSourceFlag, err := altair.HasValidatorFlag(previousEpochParticipationByte, sourceIdx)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to get source flag from previous epoch participation for validator index `%d`", validatorIndex)
			}
			correctlyVotedSource[idx] = hasSourceFlag

			hasTargetFlag, err := altair.HasValidatorFlag(previousEpochParticipationByte, targetIdx)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to get target flag from previous epoch participation for validator index `%d`", validatorIndex)
			}
			correctlyVotedTarget[idx] = hasTargetFlag

			hasHeadFlag, err := altair.HasValidatorFlag(previousEpochParticipationByte, headIdx)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to get head flag from previous epoch participation for validator index `%d`", validatorIndex)
			}
			correctlyVotedHead[idx] = hasHeadFlag

			balanceBeforeEpochTransition, err := strconv.ParseUint(altairBeaconState.Balances[validatorIndex], 10, 64)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to parse balance before epoch transition `%s` for validator index `%d`", altairBeaconState.Balances[validatorIndex], validatorIndex)
			}

			// TODO (pavignol): Correctly query the balances before epoch transition
			balancesBeforeEpochTransition[idx] = balanceBeforeEpochTransition
		}
	case "bellatrix":
		bellatrixBeaconState := apimiddleware.BeaconStateBellatrixJson{}
		if err := decoder.Decode(&bellatrixBeaconState); err != nil {
			return nil, errors.Wrap(err, "failed to decode bellatrix beacon state response json")
		}
	case "capella":
		capellaBeaconState := apimiddleware.BeaconStateCapellaJson{}
		if err := decoder.Decode(&capellaBeaconState); err != nil {
			return nil, errors.Wrap(err, "failed to decode capella beacon state response json")
		}
	}

	validatorPerformanceResponse := &ethpb.ValidatorPerformanceResponse{
		CurrentEffectiveBalances:      currentEffectiveBalances,
		CorrectlyVotedSource:          correctlyVotedSource,
		CorrectlyVotedTarget:          correctlyVotedTarget,
		CorrectlyVotedHead:            correctlyVotedHead,
		BalancesBeforeEpochTransition: balancesBeforeEpochTransition,
		BalancesAfterEpochTransition:  balancesBeforeEpochTransition, // TODO (pavignol): Correctly query the balances before epoch transition
		MissingValidators:             [][]byte{},                    // TODO (pavignol): Figure out which validators are missing
		AverageActiveValidatorBalance: float32(activeValidatorBalanceSum) / float32(activeValidatorCount),
		PublicKeys:                    in.PublicKeys,
	}

	marshalledRest, err := json.Marshal(validatorPerformanceResponse)
	if err != nil {
		return nil, err
	}

	grpcResponse, err := c.fallbackClient.GetValidatorPerformance(ctx, in)
	if err != nil {
		return nil, err
	}

	marshalledGrpc, err := json.Marshal(grpcResponse)
	if err != nil {
		return nil, err
	}

	log.Errorf("*****************GRPC: %s", string(marshalledGrpc))
	log.Errorf("*****************REST: %s", string(marshalledRest))

	return validatorPerformanceResponse, nil
}

func (c beaconApiBeaconChainClient) GetValidatorParticipation(ctx context.Context, in *ethpb.GetValidatorParticipationRequest) (*ethpb.ValidatorParticipationResponse, error) {
	if c.fallbackClient != nil {
		return c.fallbackClient.GetValidatorParticipation(ctx, in)
	}

	// TODO: Implement me
	panic("beaconApiBeaconChainClient.GetValidatorParticipation is not implemented. To use a fallback client, pass a fallback client as the last argument of NewBeaconApiBeaconChainClientWithFallback.")
}

func NewBeaconApiBeaconChainClientWithFallback(host string, timeout time.Duration, fallbackClient iface.BeaconChainClient) iface.BeaconChainClient {
	jsonRestHandler := beaconApiJsonRestHandler{
		httpClient: http.Client{Timeout: timeout},
		host:       host,
	}

	return &beaconApiBeaconChainClient{
		jsonRestHandler:         jsonRestHandler,
		fallbackClient:          fallbackClient,
		stateValidatorsProvider: beaconApiStateValidatorsProvider{jsonRestHandler: jsonRestHandler},
	}
}
