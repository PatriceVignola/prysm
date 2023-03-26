package beacon_api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/pkg/errors"
	"github.com/prysmaticlabs/prysm/v4/beacon-chain/core/altair"
	"github.com/prysmaticlabs/prysm/v4/beacon-chain/rpc/apimiddleware"
	"github.com/prysmaticlabs/prysm/v4/config/params"
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

	indices := make([]int64, len(in.Indices))
	for index, validatorIndex := range in.Indices {
		indices[index] = int64(validatorIndex)
	}

	stateValidatorsResponse, err := c.stateValidatorsProvider.GetStateValidators(ctx, nil, indices, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get head state validators for indices `%v`", indices)
	}

	cfg := params.BeaconConfig()
	targetIdx := cfg.TimelyTargetFlagIndex
	sourceIdx := cfg.TimelySourceFlagIndex
	headIdx := cfg.TimelyHeadFlagIndex

	var activeValidatorBalanceSum uint64
	var activeValidatorCount uint64
	currentEffectiveBalances := make([]uint64, len(indices))
	for index, stateValidator := range stateValidatorsResponse.Data {
		if stateValidator == nil || stateValidator.Validator == nil {
			return nil, errors.New("state validator is nil")
		}

		currentEffectiveBalance, err := strconv.ParseUint(stateValidator.Validator.EffectiveBalance, 10, 64)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse validator effective balance `%s`", stateValidator.Validator.EffectiveBalance)
		}

		currentEffectiveBalances[index] = currentEffectiveBalance

		balance, err := strconv.ParseUint(stateValidator.Balance, 10, 64)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse balance `%s` for validator index `%s`", stateValidator.Balance, stateValidator.Index)
		}

		if strings.HasPrefix(stateValidator.Status, "active_") {
			activeValidatorBalanceSum += balance
			activeValidatorCount++
		}
	}

	correctlyVotedSource := make([]bool, len(indices))
	correctlyVotedTarget := make([]bool, len(indices))
	correctlyVotedHead := make([]bool, len(indices))
	balancesBeforeEpochTransition := make([]uint64, len(indices))

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

		for _, validatorIndex := range indices {
			if int(validatorIndex) >= len(altairBeaconState.PreviousEpochParticipation) {
				return nil, errors.Errorf("validator index `%d` is too big for length `%d` of the current epoch participations", validatorIndex, len(altairBeaconState.CurrentEpochParticipation))
			}

			previousEpochParticipationString := altairBeaconState.PreviousEpochParticipation[validatorIndex]
			previousEpochParticipation, err := strconv.ParseUint(previousEpochParticipationString, 10, 8)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to parse current epoch participation `%s`", previousEpochParticipationString)
			}

			previousEpochParticipationByte := byte(previousEpochParticipation)

			hasSourceFlag, err := altair.HasValidatorFlag(previousEpochParticipationByte, sourceIdx)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to get source flag from previous epoch participation for validator index `%d`", validatorIndex)
			}
			correctlyVotedSource[validatorIndex] = hasSourceFlag

			hasTargetFlag, err := altair.HasValidatorFlag(previousEpochParticipationByte, targetIdx)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to get target flag from previous epoch participation for validator index `%d`", validatorIndex)
			}
			correctlyVotedTarget[validatorIndex] = hasTargetFlag

			hasHeadFlag, err := altair.HasValidatorFlag(previousEpochParticipationByte, headIdx)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to get head flag from previous epoch participation for validator index `%d`", validatorIndex)
			}
			correctlyVotedHead[validatorIndex] = hasHeadFlag

			balanceBeforeEpochTransition, err := strconv.ParseUint(altairBeaconState.Balances[validatorIndex], 10, 64)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to parse balance before epoch transition `%d` for validator index `%d`", altairBeaconState.Balances[validatorIndex], validatorIndex)
			}

			// TODO (pavignol): Correctly query the balances before epoch transition
			balancesBeforeEpochTransition[validatorIndex] = balanceBeforeEpochTransition
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

	return &ethpb.ValidatorPerformanceResponse{
		CurrentEffectiveBalances:      currentEffectiveBalances,
		CorrectlyVotedSource:          correctlyVotedSource,
		CorrectlyVotedTarget:          correctlyVotedTarget,
		CorrectlyVotedHead:            correctlyVotedHead,
		BalancesBeforeEpochTransition: balancesBeforeEpochTransition,
		BalancesAfterEpochTransition:  balancesBeforeEpochTransition, // TODO (pavignol): Correctly query the balances before epoch transition
		MissingValidators:             [][]byte{},                    // TODO (pavignol): Figure out which validators are missing
		AverageActiveValidatorBalance: float32(activeValidatorBalanceSum) / float32(activeValidatorCount),
	}, nil
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
