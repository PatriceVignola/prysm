package beacon_api

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/pkg/errors"
	"github.com/prysmaticlabs/go-bitfield"
	"github.com/prysmaticlabs/prysm/v4/beacon-chain/core/altair"
	"github.com/prysmaticlabs/prysm/v4/beacon-chain/core/epoch/precompute"
	"github.com/prysmaticlabs/prysm/v4/beacon-chain/rpc/apimiddleware"
	"github.com/prysmaticlabs/prysm/v4/config/params"
	"github.com/prysmaticlabs/prysm/v4/consensus-types/primitives"
	math2 "github.com/prysmaticlabs/prysm/v4/math"
	ethpb "github.com/prysmaticlabs/prysm/v4/proto/prysm/v1alpha1"
	"github.com/prysmaticlabs/prysm/v4/proto/prysm/v1alpha1/attestation"
	"github.com/prysmaticlabs/prysm/v4/time/slots"
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

func BlockRoot(state apimiddleware.BeaconStateJson, epoch primitives.Epoch) (string, error) {
	s, err := slots.EpochStart(epoch)
	if err != nil {
		return "", err
	}
	return BlockRootAtSlot(state, s)
}

func BlockRootAtSlot(state apimiddleware.BeaconStateJson, slot primitives.Slot) (string, error) {
	if math.MaxUint64-slot < params.BeaconConfig().SlotsPerHistoricalRoot {
		return "", errors.New("slot overflows uint64")
	}

	stateSlot, err := strconv.ParseUint(state.Slot, 10, 64)
	if err != nil {
		return "", errors.Wrapf(err, "failed to parse slot `%s`", state.Slot)
	}

	if slot >= primitives.Slot(stateSlot) || primitives.Slot(stateSlot) > slot+params.BeaconConfig().SlotsPerHistoricalRoot {
		return "", errors.Errorf("slot %d out of bounds", slot)
	}

	return state.BlockRoots[uint64(slot%params.BeaconConfig().SlotsPerHistoricalRoot)], nil
}

func (c beaconApiBeaconChainClient) getPhase0CorrectlyVotedAttestations(
	ctx context.Context,
	phase0BeaconState apimiddleware.BeaconStateJson,
) ([]bool, []bool, []bool, error) {
	justifiedCheckpoint := phase0BeaconState.PreviousJustifiedCheckpoint
	if justifiedCheckpoint == nil {
		return nil, nil, nil, errors.New("previous justified checkpoint is nil")
	}

	correctlyVotedSource := make([]bool, len(phase0BeaconState.Validators))
	correctlyVotedTarget := make([]bool, len(phase0BeaconState.Validators))
	correctlyVotedHead := make([]bool, len(phase0BeaconState.Validators))

	cfg := params.BeaconConfig()
	for _, previousEpochAttestation := range phase0BeaconState.PreviousEpochAttestations {
		if previousEpochAttestation == nil {
			return nil, nil, nil, errors.New("previous epoch attestation is nil")
		}

		data := previousEpochAttestation.Data
		if data == nil {
			return nil, nil, nil, errors.New("previous epoch attestation data is nil")
		}

		inclusionDelay, err := strconv.ParseUint(previousEpochAttestation.InclusionDelay, 10, 64)
		if err != nil {
			return nil, nil, nil, errors.Wrapf(err, "failed to parse previous epoch attestation inclusion delay `%s`", previousEpochAttestation.InclusionDelay)
		}

		targetEpoch, err := strconv.ParseUint(data.Target.Epoch, 10, 64)
		if err != nil {
			return nil, nil, nil, errors.Wrapf(err, "failed to parse target epoch `%s`", data.Target.Epoch)
		}

		targetBlockRoot, err := BlockRoot(phase0BeaconState, primitives.Epoch(targetEpoch))
		if err != nil {
			return nil, nil, nil, errors.Wrapf(err, "failed to retrieve block root for target epoch `%d`", targetEpoch)
		}

		attestationSlot, err := strconv.ParseUint(data.Slot, 10, 64)
		if err != nil {
			return nil, nil, nil, errors.Wrapf(err, "failed to parse previous epoch attestation slot `%s`", data.Slot)
		}

		attestationBlockRoot, err := BlockRootAtSlot(phase0BeaconState, primitives.Slot(attestationSlot))
		if err != nil {
			return nil, nil, nil, errors.Wrapf(err, "failed to retrieve block root for previous attestation slot `%d`", attestationSlot)
		}

		isMatchingSource := data.Source.Epoch == justifiedCheckpoint.Epoch && data.Source.Root == justifiedCheckpoint.Root
		isMatchingTarget := isMatchingSource && data.Target.Root == targetBlockRoot
		isMatchingHead := isMatchingTarget && data.BeaconBlockRoot == attestationBlockRoot

		hasSourceFlag := isMatchingSource && primitives.Slot(inclusionDelay) <= cfg.SqrRootSlotsPerEpoch
		hasTargetFlag := isMatchingTarget && primitives.Slot(inclusionDelay) <= cfg.SlotsPerEpoch
		hasHeadFlag := isMatchingHead && primitives.Slot(inclusionDelay) <= cfg.MinAttestationInclusionDelay

		aggregationBits, err := hexutil.Decode(previousEpochAttestation.AggregationBits)
		if err != nil {
			return nil, nil, nil, errors.Wrapf(err, "failed to decode aggregation bits `%s`", aggregationBits)
		}

		slot, err := strconv.ParseUint(data.Slot, 10, 64)
		if err != nil {
			return nil, nil, nil, errors.Wrapf(err, "failed to parse slot `%s`", data.Slot)
		}

		previousEpoch := slots.ToEpoch(primitives.Slot(slot)) - 1

		committeeIndex, err := strconv.ParseUint(data.CommitteeIndex, 10, 64)
		if err != nil {
			return nil, nil, nil, errors.Wrapf(err, "failed to parse committee index `%s`", data.CommitteeIndex)
		}

		committee, err := c.getCommittee(ctx, previousEpoch, primitives.Slot(slot), primitives.CommitteeIndex(committeeIndex))
		if err != nil {
			return nil, nil, nil, errors.Wrapf(err, "failed to get committee index `%d` for epoch `%d`", committeeIndex, previousEpoch)
		}

		committeeValidators := make([]primitives.ValidatorIndex, len(committee.Validators))
		for idx, validatorIndexString := range committee.Validators {
			validatorIndex, err := strconv.ParseUint(validatorIndexString, 10, 64)
			if err != nil {
				return nil, nil, nil, errors.Wrapf(err, "failed to parse validator index `%s`", validatorIndexString)
			}

			committeeValidators[idx] = primitives.ValidatorIndex(validatorIndex)
		}

		// TODO (pavignol): Make sure endianness of aggregationBits is correct
		attestingIndices, err := attestation.AttestingIndices(bitfield.Bitlist(aggregationBits), committeeValidators)
		if err != nil {
			return nil, nil, nil, errors.Wrap(err, "failed to get attesting indices")
		}

		for _, attestingIndex := range attestingIndices {
			if attestingIndex >= uint64(len(correctlyVotedSource)) {
				return nil, nil, nil, errors.Errorf("attesting index `%d` is out of bounds", attestingIndex)
			}

			correctlyVotedSource[attestingIndex] = hasSourceFlag
			correctlyVotedTarget[attestingIndex] = hasTargetFlag
			correctlyVotedHead[attestingIndex] = hasHeadFlag
		}
	}

	return correctlyVotedSource, correctlyVotedTarget, correctlyVotedHead, nil
}

func (c beaconApiBeaconChainClient) getCommittee(ctx context.Context, epoch primitives.Epoch, slot primitives.Slot, committeeIndex primitives.CommitteeIndex) (*apimiddleware.CommitteeJson, error) {
	committeeParams := url.Values{}
	committeeParams.Add("epoch", strconv.FormatUint(uint64(epoch), 10))
	committeeParams.Add("slot", strconv.FormatUint(uint64(slot), 10))
	committeeParams.Add("index", strconv.FormatUint(uint64(committeeIndex), 10))
	committeesRequest := buildURL("/eth/v1/beacon/states/head/committees", committeeParams)

	var stateCommittees apimiddleware.StateCommitteesResponseJson
	if _, err := c.jsonRestHandler.GetRestJsonResponse(ctx, committeesRequest, &stateCommittees); err != nil {
		return nil, errors.Wrapf(err, "failed to query committees for epoch `%d`", epoch)
	}

	if stateCommittees.Data == nil {
		return nil, errors.New("state committees data is nil")
	}

	if len(stateCommittees.Data) != 1 {
		return nil, errors.Errorf("1 committee was expected, but %d were received", len(stateCommittees.Data))
	}

	if stateCommittees.Data[0] == nil {
		return nil, errors.New("committee data is nil")
	}

	return stateCommittees.Data[0], nil
}

func inactivityPenaltyQuotient(beaconState interface{}) (uint64, error) {
	switch beaconState.(type) {
	case apimiddleware.BeaconStateBellatrixJson, apimiddleware.BeaconStateAltairJson:
		return params.BeaconConfig().InactivityPenaltyQuotientBellatrix, nil
	case *apimiddleware.BeaconStateAltairJson:
		return params.BeaconConfig().InactivityPenaltyQuotientAltair, nil
	case apimiddleware.BeaconStateJson:
		return params.BeaconConfig().InactivityPenaltyQuotient, nil
	}
	return 0, errors.New("unsupported beacon state type")
}

func (c beaconApiBeaconChainClient) getAttestationDelta(
	ctx context.Context,
	beaconState apimiddleware.BeaconStateJson,
	correctlyVotedSource bool,
	correctlyVotedTarget bool,
	correctlyVotedHead bool,
	validator *apimiddleware.ValidatorJson,
	inactivityScores uint64,
	activeCurrentEpochEffectiveBalance uint64,
	prevEpochSourceAttestedEffectiveBalance uint64,
	prevEpochTargetAttestedEffectiveBalance uint64,
	prevEpochHeadAttestedEffectiveBalance uint64,
	validatorPubkeyToIndex map[string]primitives.ValidatorIndex,
) (uint64, uint64, error) {
	currentSlot, err := strconv.ParseUint(beaconState.Slot, 10, 64)
	if err != nil {
		return 0, 0, errors.Wrapf(err, "failed to parse beacon state slot `%s`", beaconState.Slot)
	}
	currentEpoch := slots.ToEpoch(primitives.Slot(currentSlot))

	// cfg := params.BeaconConfig()
	prevEpoch := currentEpoch - 1

	finalizedEpoch, err := strconv.ParseUint(beaconState.FinalizedCheckpoint.Epoch, 10, 64)
	if err != nil {
		return 0, 0, errors.Wrapf(err, "failed to parse epoch `%s`", beaconState.FinalizedCheckpoint.Epoch)
	}
	// increment := cfg.EffectiveBalanceIncrement
	// factor := cfg.BaseRewardFactor
	// baseRewardMultiplier := increment * factor / math2.CachedSquareRoot(uint64(currentEpoch))
	// leak := helpers.IsInInactivityLeak(prevEpoch, primitives.Epoch(finalizedEpoch))

	// Modified in Altair and Bellatrix.
	// bias := cfg.InactivityScoreBias
	// inactivityPenaltyQuotient, err := inactivityPenaltyQuotient(beaconState)
	// if err != nil {
	// 	return 0, 0, err
	// }
	// inactivityDenominator := bias * inactivityPenaltyQuotient

	balance := &precompute.Balance{
		ActiveCurrentEpoch:      activeCurrentEpochEffectiveBalance,
		PrevEpochAttested:       prevEpochSourceAttestedEffectiveBalance,
		PrevEpochTargetAttested: prevEpochTargetAttestedEffectiveBalance,
		PrevEpochHeadAttested:   prevEpochHeadAttestedEffectiveBalance,
	}

	withdrawableEpoch, err := strconv.ParseUint(validator.WithdrawableEpoch, 10, 64)
	if err != nil {
		return 0, 0, errors.Wrapf(err, "failed to parse withdrawable epoch `%s`", validator.WithdrawableEpoch)
	}

	effectiveBalance, err := strconv.ParseUint(validator.EffectiveBalance, 10, 64)
	if err != nil {
		return 0, 0, errors.Wrapf(err, "failed to parse effective balance `%s`", validator.EffectiveBalance)
	}

	var inclusionDelay uint64

	// TODO (pavignol): Get this loop out and cache the results
	for _, pendingAttestation := range beaconState.CurrentEpochAttestations {
		committeeIndex, err := strconv.ParseUint(pendingAttestation.Data.CommitteeIndex, 10, 64)
		if err != nil {
			return 0, 0, errors.Wrapf(err, "failed to parse committee index `%s`", pendingAttestation.Data.CommitteeIndex)
		}

		committee, err := c.getCommittee(ctx, currentEpoch, primitives.Slot(currentSlot), primitives.CommitteeIndex(committeeIndex))
		if err != nil {
			return 0, 0, errors.Wrapf(err, "failed to get committee index `%d` for epoch `%d`", committeeIndex, currentEpoch)
		}

		committeeValidators := make([]primitives.ValidatorIndex, len(committee.Validators))
		for idx, validatorIndexString := range committee.Validators {
			validatorIndex, err := strconv.ParseUint(validatorIndexString, 10, 64)
			if err != nil {
				return 0, 0, errors.Wrapf(err, "failed to parse validator index `%s`", validatorIndexString)
			}

			committeeValidators[idx] = primitives.ValidatorIndex(validatorIndex)
		}

		aggregationBits, err := hexutil.Decode(pendingAttestation.AggregationBits)
		if err != nil {
			return 0, 0, errors.Wrapf(err, "failed to decode aggregation bits `%s`", aggregationBits)
		}

		// TODO (pavignol): Make sure endianness of aggregationBits is correct
		attestingIndices, err := attestation.AttestingIndices(bitfield.Bitlist(aggregationBits), committeeValidators)
		if err != nil {
			return 0, 0, errors.Wrap(err, "failed to get attesting indices")
		}

		foundValidator := false

		for _, attestingIndex := range attestingIndices {
			validatorIndex, ok := validatorPubkeyToIndex[validator.PublicKey]
			if !ok {
				return 0, 0, errors.Errorf("failed to get validator index for validator `%s`", validator.PublicKey)
			}

			if attestingIndex == uint64(validatorIndex) {
				foundValidator = true

				inclusionDelay, err = strconv.ParseUint(pendingAttestation.InclusionDelay, 10, 64)
				if err != nil {
					return 0, 0, errors.Wrapf(err, "failed to parse inclusion delay `%s`", pendingAttestation.InclusionDelay)
				}
				break
			}
		}

		if foundValidator {
			break
		}
	}

	sqrtActiveCurrentEpoch := math2.CachedSquareRoot(balance.ActiveCurrentEpoch)
	precomputeValidator := &precompute.Validator{
		IsSlashed:                    validator.Slashed,
		IsWithdrawableCurrentEpoch:   primitives.Epoch(withdrawableEpoch) == currentEpoch,
		IsActivePrevEpoch:            true, // TODO (pavignol): Fix
		IsPrevEpochAttester:          correctlyVotedSource,
		IsPrevEpochTargetAttester:    correctlyVotedTarget,
		IsPrevEpochHeadAttester:      correctlyVotedHead,
		CurrentEpochEffectiveBalance: effectiveBalance,
		InclusionDistance:            primitives.Slot(inclusionDelay),
	}

	rewards, penalties := precompute.AttestationDelta(balance, sqrtActiveCurrentEpoch, precomputeValidator, prevEpoch, primitives.Epoch(finalizedEpoch))
	return rewards, penalties, nil

	/*
		return attestationDelta(
			currentEpoch,
			correctlyVotedSource,
			correctlyVotedTarget,
			correctlyVotedHead,
			validator,
			baseRewardMultiplier,
			inactivityDenominator,
			leak,
			inactivityScores,
			activeCurrentEpochEffectiveBalance,
			prevEpochSourceAttestedEffectiveBalance,
			prevEpochTargetAttestedEffectiveBalance,
			prevEpochHeadAttestedEffectiveBalance,
		)
	*/
}

func attestationDelta(
	currentEpoch primitives.Epoch,
	correctlyVotedSource bool,
	correctlyVotedTarget bool,
	correctlyVotedHead bool,
	val *apimiddleware.ValidatorJson,
	baseRewardMultiplier uint64,
	inactivityDenominator uint64,
	inactivityLeak bool,
	inactivityScore uint64,
	activeCurrentEpochEffectiveBalance uint64,
	prevEpochSourceAttestedEffectiveBalance uint64,
	prevEpochTargetAttestedEffectiveBalance uint64,
	prevEpochHeadAttestedEffectiveBalance uint64,
) (reward, penalty uint64, err error) {

	withdrawableEpoch, err := strconv.ParseUint(val.WithdrawableEpoch, 10, 64)
	if err != nil {
		return 0, 0, errors.Wrapf(err, "failed to parse withdrawable epoch `%s`", val.WithdrawableEpoch)
	}

	// TODO (pavignol): Fix
	activePrevEpoch := true

	eligible := activePrevEpoch || (val.Slashed && primitives.Epoch(withdrawableEpoch) != currentEpoch)
	// Per spec `ActiveCurrentEpoch` can't be 0 to process attestation delta.
	if !eligible || activeCurrentEpochEffectiveBalance == 0 {
		return 0, 0, nil
	}

	cfg := params.BeaconConfig()
	increment := cfg.EffectiveBalanceIncrement
	effectiveBalance, err := strconv.ParseUint(val.EffectiveBalance, 10, 64)
	if err != nil {
		return 0, 0, errors.Wrapf(err, "failed to parse effective balance `%s`", val.EffectiveBalance)
	}

	baseReward := (effectiveBalance / increment) * baseRewardMultiplier
	activeIncrement := activeCurrentEpochEffectiveBalance / increment

	log.Errorf("*********attestationDelta (REST) validator: %s", val.PublicKey)
	log.Errorf("*********attestationDelta (REST) effectiveBalance: %d", effectiveBalance)
	log.Errorf("*********attestationDelta (REST) baseReward: %d", baseReward)
	log.Errorf("*********attestationDelta (REST) prevEpochSourceAttestedEffectiveBalance: %d", prevEpochSourceAttestedEffectiveBalance)
	log.Errorf("*********attestationDelta (REST) prevEpochTargetAttestedEffectiveBalance: %d", prevEpochTargetAttestedEffectiveBalance)
	log.Errorf("*********attestationDelta (REST) prevEpochHeadAttestedEffectiveBalance: %d", prevEpochHeadAttestedEffectiveBalance)
	log.Errorf("*********attestationDelta (REST) activeCurrentEpochEffectiveBalance: %d", activeCurrentEpochEffectiveBalance)
	log.Errorf("*********attestationDelta (REST) baseRewardMultiplier: %d", baseRewardMultiplier)
	log.Errorf("******************************************************************************")
	log.Errorf("******************************************************************************")
	log.Errorf("******************************************************************************")
	log.Errorf("******************************************************************************")
	log.Errorf("******************************************************************************")
	log.Errorf("******************************************************************************")

	weightDenominator := cfg.WeightDenominator
	srcWeight := cfg.TimelySourceWeight
	tgtWeight := cfg.TimelyTargetWeight
	headWeight := cfg.TimelyHeadWeight
	reward, penalty = uint64(0), uint64(0)
	// Process source reward / penalty
	// if val.IsPrevEpochSourceAttester && !val.Slashed {
	if correctlyVotedSource && !val.Slashed {
		if !inactivityLeak {
			n := baseReward * srcWeight * (prevEpochSourceAttestedEffectiveBalance / increment)
			reward += n / (activeIncrement * weightDenominator)
		}
	} else {
		penalty += baseReward * srcWeight / weightDenominator
	}

	// Process target reward / penalty
	// if val.IsPrevEpochTargetAttester && !val.Slashed {
	if correctlyVotedTarget && !val.Slashed {
		if !inactivityLeak {
			n := baseReward * tgtWeight * (prevEpochTargetAttestedEffectiveBalance / increment)
			reward += n / (activeIncrement * weightDenominator)
		}
	} else {
		penalty += baseReward * tgtWeight / weightDenominator
	}

	// Process head reward / penalty
	// if val.IsPrevEpochHeadAttester && !val.Slashed {
	if correctlyVotedHead && !val.Slashed {
		if !inactivityLeak {
			n := baseReward * headWeight * (prevEpochHeadAttestedEffectiveBalance / increment)
			reward += n / (activeIncrement * weightDenominator)
		}
	}

	// Process finality delay penalty
	// Apply an additional penalty to validators that did not vote on the correct target or slashed
	if !correctlyVotedTarget || val.Slashed {
		n, err := math2.Mul64(effectiveBalance, inactivityScore)
		if err != nil {
			return 0, 0, err
		}
		penalty += n / inactivityDenominator
	}

	return reward, penalty, nil
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

	var currentEpochSlot primitives.Slot

	var beaconState interface{}
	inactivityScores := make([]uint64, len(pubkeys))

	switch beaconStateJson.Version {
	case "phase0":
		phase0BeaconState := apimiddleware.BeaconStateJson{}
		if err := decoder.Decode(&phase0BeaconState); err != nil {
			return nil, errors.Wrap(err, "failed to decode phase0 beacon state response json")
		}
		beaconState = phase0BeaconState

		slot, err := strconv.ParseUint(phase0BeaconState.Slot, 10, 64)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse beacon state slot `%s`", phase0BeaconState.Slot)
		}
		currentEpochSlot = primitives.Slot(slot)

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

	currentStateValidatorsResponse, err := c.stateValidatorsProvider.GetStateValidatorsForSlot(ctx, currentEpochSlot, pubkeys, nil, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get current state validators for slot `%d` and indices `%v`", currentEpochSlot, in.PublicKeys)
	}

	// The spec doesn't guarantee that validators returned from /eth/v1/beacon/states/{state_id}/validators will be returned in the same order
	// as the input indices, so we need to have this mapping
	validatorPubkeyToArrayIndex := make(map[string]int, len(pubkeys))
	for idx, pubkey := range pubkeys {
		validatorPubkeyToArrayIndex[pubkey] = idx
	}

	cfg := params.BeaconConfig()
	targetIdx := cfg.TimelyTargetFlagIndex
	sourceIdx := cfg.TimelySourceFlagIndex
	headIdx := cfg.TimelyHeadFlagIndex

	balancesBeforeEpochTransition := make([]uint64, len(pubkeys))
	balancesAfterEpochTransition := make([]uint64, len(pubkeys))
	var activeValidatorBalanceSum uint64
	var activeValidatorCount uint64

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

		// TODO (pavignol): remove if average balance isn't needed
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

	currentEffectiveBalances := make([]uint64, len(pubkeys))

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

	correctlyVotedSource := make([]bool, len(pubkeys))
	correctlyVotedTarget := make([]bool, len(pubkeys))
	correctlyVotedHead := make([]bool, len(pubkeys))

	switch beaconState := beaconState.(type) {
	case apimiddleware.BeaconStateJson:
		correctlyVotedSourceAllValidators, correctlyVotedTargetAllValidators, correctlyVotedHeadAllValidators, err := c.getPhase0CorrectlyVotedAttestations(ctx, beaconState)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get phase0 correctly voted attestations")
		}

		var prevEpochSourceAttestedEffectiveBalance uint64
		var prevEpochTargetAttestedEffectiveBalance uint64
		var prevEpochHeadAttestedEffectiveBalance uint64
		var currentEpochActiveEffectiveBalance uint64

		for idx := range correctlyVotedSourceAllValidators {
			effectiveBalance, err := strconv.ParseUint(beaconState.Validators[idx].EffectiveBalance, 10, 64)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to parse effective balance `%s`", beaconState.Validators[idx].EffectiveBalance)
			}

			if correctlyVotedSourceAllValidators[idx] {
				prevEpochSourceAttestedEffectiveBalance += effectiveBalance
			}

			if correctlyVotedTargetAllValidators[idx] {
				prevEpochTargetAttestedEffectiveBalance += effectiveBalance
			}

			if correctlyVotedHeadAllValidators[idx] {
				prevEpochHeadAttestedEffectiveBalance += effectiveBalance
			}

			currentEpochActiveEffectiveBalance += effectiveBalance
		}

		for idx, validatorPubKey := range pubkeys {
			validatorIndex, ok := validatorPubkeyToIndex[validatorPubKey]
			if !ok {
				return nil, errors.Errorf("failed to get index for validator `%s`", validatorPubKey)
			}

			correctlyVotedSource[idx] = correctlyVotedSourceAllValidators[validatorIndex]
			correctlyVotedTarget[idx] = correctlyVotedTargetAllValidators[validatorIndex]
			correctlyVotedHead[idx] = correctlyVotedHeadAllValidators[validatorIndex]

			effectiveBalance, err := strconv.ParseUint(beaconState.Validators[validatorIndex].EffectiveBalance, 10, 64)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to parse effective balance `%s` for validator index `%d`", beaconState.Validators[validatorIndex].EffectiveBalance, validatorIndex)
			}

			currentEffectiveBalances[idx] = effectiveBalance

			attsRewards, attsPenalties, err := c.getAttestationDelta(
				ctx,
				beaconState,
				correctlyVotedSourceAllValidators[validatorIndex],
				correctlyVotedTargetAllValidators[validatorIndex],
				correctlyVotedHeadAllValidators[validatorIndex],
				beaconState.Validators[validatorIndex],
				inactivityScores[idx],
				currentEpochActiveEffectiveBalance,
				prevEpochSourceAttestedEffectiveBalance,
				prevEpochTargetAttestedEffectiveBalance,
				prevEpochHeadAttestedEffectiveBalance,
				validatorPubkeyToIndex,
			)
			if err != nil {
				return nil, errors.Wrap(err, "could not get attestation delta")
			}

			balance, err := strconv.ParseUint(beaconState.Balances[validatorIndex], 10, 64)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to parse balance before epoch transition `%s` for validator `%s`", beaconState.Balances[validatorIndex], validatorPubKey)
			}

			balancesAfterEpochTransition[idx] = balance + attsRewards - attsPenalties
		}

	case apimiddleware.BeaconStateAltairJson:
		for idx, validatorPubKey := range pubkeys {
			validatorIndex, ok := validatorPubkeyToIndex[validatorPubKey]
			if !ok {
				return nil, errors.Errorf("failed to get index for validator `%s`", validatorPubKey)
			}

			if uint64(validatorIndex) >= uint64(len(beaconState.PreviousEpochParticipation)) {
				return nil, errors.Errorf("validator index `%d` is too big for length `%d` of the previous epoch participations", validatorIndex, len(beaconState.PreviousEpochParticipation))
			}

			previousEpochParticipationString := beaconState.PreviousEpochParticipation[validatorIndex]
			previousEpochParticipation, err := strconv.ParseUint(previousEpochParticipationString, 10, 8)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to parse previous epoch participation `%s`", previousEpochParticipationString)
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

			beaconStateValidatorsLength := len(beaconState.Validators)
			if uint64(validatorIndex) >= uint64(beaconStateValidatorsLength) {
				return nil, errors.Errorf("validator index `%d` is too big for length `%d` of the previous epoch participations", validatorIndex, beaconStateValidatorsLength)
			}

			effectiveBalance, err := strconv.ParseUint(beaconState.Validators[validatorIndex].EffectiveBalance, 10, 64)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to parse effective balance `%s` for validator index `%d`", beaconState.Validators[validatorIndex].EffectiveBalance, validatorIndex)
			}
			currentEffectiveBalances[idx] = effectiveBalance
		}
	case apimiddleware.BeaconStateBellatrixJson:
	case apimiddleware.BeaconStateCapellaJson:
	}

	validatorPerformanceResponse := &ethpb.ValidatorPerformanceResponse{
		CurrentEffectiveBalances:      currentEffectiveBalances,
		CorrectlyVotedSource:          correctlyVotedSource,
		CorrectlyVotedTarget:          correctlyVotedTarget,
		CorrectlyVotedHead:            correctlyVotedHead,
		BalancesBeforeEpochTransition: balancesBeforeEpochTransition,
		BalancesAfterEpochTransition:  balancesAfterEpochTransition, // TODO (pavignol): Correctly query the balances before epoch transition
		MissingValidators:             [][]byte{},                   // TODO (pavignol): Figure out which validators are missing
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
