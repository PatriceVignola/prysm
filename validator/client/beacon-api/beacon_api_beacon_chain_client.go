package beacon_api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/pkg/errors"
	"github.com/prysmaticlabs/prysm/v4/beacon-chain/rpc/apimiddleware"
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

	var currentSlot primitives.Slot

	var beaconState interface{}
	// inactivityScores := make([]uint64, len(pubkeys))
	// TODO (pavignol): Convert phase0 beacon statein terms of altair/bellatrix/capella

	switch beaconStateJson.Version {
	case "phase0":
		phase0BeaconState := apimiddleware.BeaconStateJson{}
		if err := decoder.Decode(&phase0BeaconState); err != nil {
			return nil, errors.Wrap(err, "failed to decode phase0 beacon state response json")
		}

		slot, err := strconv.ParseUint(phase0BeaconState.Slot, 10, 64)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse beacon state slot `%s`", phase0BeaconState.Slot)
		}
		currentSlot = primitives.Slot(slot)
		beaconState = phase0BeaconState

	case "altair":
		altairBeaconState := apimiddleware.BeaconStateAltairJson{}
		if err := decoder.Decode(&altairBeaconState); err != nil {
			return nil, errors.Wrap(err, "failed to decode altair beacon state response json")
		}
		beaconState = altairBeaconState

	case "bellatrix":
		bellatrixBeaconState := apimiddleware.BeaconStateBellatrixJson{}
		if err := decoder.Decode(&bellatrixBeaconState); err != nil {
			return nil, errors.Wrap(err, "failed to decode bellatrix beacon state response json")
		}
		beaconState = bellatrixBeaconState
	case "capella":
		capellaBeaconState := apimiddleware.BeaconStateCapellaJson{}
		if err := decoder.Decode(&capellaBeaconState); err != nil {
			return nil, errors.Wrap(err, "failed to decode capella beacon state response json")
		}
		beaconState = capellaBeaconState
	}

	currentStateValidatorsResponse, err := c.stateValidatorsProvider.GetStateValidatorsForSlot(ctx, currentSlot, pubkeys, nil, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get current state validators for slot `%d` and indices `%v`", currentSlot, in.PublicKeys)
	}

	// The spec doesn't guarantee that validators returned from /eth/v1/beacon/states/{state_id}/validators will be returned in the same order
	// as the input indices, so we need to have this mapping
	validatorPubkeyToArrayIndex := make(map[string]int, len(pubkeys))
	for idx, pubkey := range pubkeys {
		validatorPubkeyToArrayIndex[pubkey] = idx
	}

	validatorIndexToArrayIndex := make(map[primitives.ValidatorIndex]int, len(pubkeys))
	currentEffectiveBalances := make([]uint64, len(pubkeys))
	balancesBeforeEpochTransition := make([]uint64, len(pubkeys))
	validators := make([]*apimiddleware.ValidatorJson, len(pubkeys))

	validatorPubkeyToIndex := make(map[string]primitives.ValidatorIndex, len(pubkeys))
	for _, stateValidator := range currentStateValidatorsResponse.Data {
		if stateValidator == nil || stateValidator.Validator == nil {
			return nil, errors.New("current state validator is nil")
		}

		idx, ok := validatorPubkeyToArrayIndex[stateValidator.Validator.PublicKey]
		if !ok {
			return nil, errors.Errorf("failed to get array index for validator `%s`", stateValidator.Validator.PublicKey)
		}

		balance, err := strconv.ParseUint(stateValidator.Balance, 10, 64)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse balance before epoch transition `%s` for validator `%s`", stateValidator.Balance, stateValidator.Validator.PublicKey)
		}

		balancesBeforeEpochTransition[idx] = balance

		validatorIndex, err := strconv.ParseUint(stateValidator.Index, 10, 64)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse state validator index `%s`", stateValidator.Index)
		}

		validatorIndexToArrayIndex[primitives.ValidatorIndex(validatorIndex)] = idx

		effectiveBalance, err := strconv.ParseUint(stateValidator.Validator.EffectiveBalance, 10, 64)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse effective balance `%s` for validator index `%d`", stateValidator.Validator.EffectiveBalance, validatorIndex)
		}
		currentEffectiveBalances[idx] = effectiveBalance

		validatorPubkeyToIndex[stateValidator.Validator.PublicKey] = primitives.ValidatorIndex(validatorIndex)
		validators[idx] = stateValidator.Validator
	}

	switch beaconState := beaconState.(type) {
	case apimiddleware.BeaconStateJson:
		return c.getPhase0ValidatorPerformance(
			ctx,
			beaconState,
			beaconStateJson.Version,
			in.PublicKeys,
			validatorPubkeyToIndex,
			validatorIndexToArrayIndex,
			currentEffectiveBalances,
			validators,
			balancesBeforeEpochTransition,
		)

	case apimiddleware.BeaconStateAltairJson:
		minimalAltairJson := minimalBeaconStateAltairJson{
			validators:                 beaconState.Validators,
			balances:                   beaconState.Balances,
			previousEpochParticipation: beaconState.PreviousEpochParticipation,
			slot:                       beaconState.Slot,
			blockRoots:                 beaconState.BlockRoots,
			finalizedCheckpoint:        beaconState.FinalizedCheckpoint,
			inactivityScores:           beaconState.InactivityScores,
		}

		return c.getAltairValidatorPerformance(
			minimalAltairJson,
			beaconStateJson.Version,
			in.PublicKeys,
			validatorPubkeyToIndex,
			validatorIndexToArrayIndex,
			currentEffectiveBalances,
			validators,
		)
	case apimiddleware.BeaconStateBellatrixJson:
		minimalAltairJson := minimalBeaconStateAltairJson{
			validators:                 beaconState.Validators,
			balances:                   beaconState.Balances,
			previousEpochParticipation: beaconState.PreviousEpochParticipation,
			slot:                       beaconState.Slot,
			blockRoots:                 beaconState.BlockRoots,
			finalizedCheckpoint:        beaconState.FinalizedCheckpoint,
			inactivityScores:           beaconState.InactivityScores,
		}

		return c.getAltairValidatorPerformance(
			minimalAltairJson,
			beaconStateJson.Version,
			in.PublicKeys,
			validatorPubkeyToIndex,
			validatorIndexToArrayIndex,
			currentEffectiveBalances,
			validators,
		)
	case apimiddleware.BeaconStateCapellaJson:
	}

	return nil, errors.Errorf("unsupported version `%s` for GetValidatorPerformance()", beaconStateJson.Version)
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
