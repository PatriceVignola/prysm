package beacon_api

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/pkg/errors"
	"github.com/prysmaticlabs/go-bitfield"
	"github.com/prysmaticlabs/prysm/v4/beacon-chain/core/altair"
	"github.com/prysmaticlabs/prysm/v4/beacon-chain/core/epoch/precompute"
	beacontime "github.com/prysmaticlabs/prysm/v4/beacon-chain/core/time"
	"github.com/prysmaticlabs/prysm/v4/beacon-chain/rpc/apimiddleware"
	"github.com/prysmaticlabs/prysm/v4/config/params"
	"github.com/prysmaticlabs/prysm/v4/consensus-types/primitives"
	ethpb "github.com/prysmaticlabs/prysm/v4/proto/prysm/v1alpha1"
	"github.com/prysmaticlabs/prysm/v4/time/slots"
)

type beaconApiMinimalState struct {
	slot                     primitives.Slot
	blockRoots               [][]byte
	finalizedCheckpointEpoch primitives.Epoch
	version                  string
}

type minimalBeaconStateAltairJson struct {
	validators                 []*apimiddleware.ValidatorJson
	balances                   []string
	previousEpochParticipation []string
	slot                       string
	blockRoots                 []string
	finalizedCheckpoint        *apimiddleware.CheckpointJson
	inactivityScores           []string
}

func NewBeaconApiMinimalState(jsonState apimiddleware.BeaconStateJson, version string) (*beaconApiMinimalState, error) {
	slot, err := strconv.ParseUint(jsonState.Slot, 10, 64)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse slot `%s`", jsonState.Slot)
	}

	blockRoots := make([][]byte, len(jsonState.BlockRoots))
	for idx, jsonBlockRoot := range jsonState.BlockRoots {
		blockRoot, err := hexutil.Decode(jsonBlockRoot)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to decode block root `%s`", jsonBlockRoot)
		}

		blockRoots[idx] = blockRoot
	}

	if jsonState.FinalizedCheckpoint == nil {
		return nil, errors.New("finalized checkpoint is nil")
	}

	finalizedEpoch, err := strconv.ParseUint(jsonState.FinalizedCheckpoint.Epoch, 10, 64)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse finalized epoch `%s`", jsonState.FinalizedCheckpoint.Epoch)
	}

	return &beaconApiMinimalState{
		slot:                     primitives.Slot(slot),
		blockRoots:               blockRoots,
		finalizedCheckpointEpoch: primitives.Epoch(finalizedEpoch),
		version:                  version,
	}, nil
}

func NewBeaconApiMinimalAltairState(jsonState minimalBeaconStateAltairJson, version string) (*beaconApiMinimalState, error) {
	slot, err := strconv.ParseUint(jsonState.slot, 10, 64)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse slot `%s`", jsonState.slot)
	}

	blockRoots := make([][]byte, len(jsonState.blockRoots))
	for idx, jsonBlockRoot := range jsonState.blockRoots {
		blockRoot, err := hexutil.Decode(jsonBlockRoot)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to decode block root `%s`", jsonBlockRoot)
		}

		blockRoots[idx] = blockRoot
	}

	if jsonState.finalizedCheckpoint == nil {
		return nil, errors.New("finalized checkpoint is nil")
	}

	finalizedEpoch, err := strconv.ParseUint(jsonState.finalizedCheckpoint.Epoch, 10, 64)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse finalized epoch `%s`", jsonState.finalizedCheckpoint.Epoch)
	}

	return &beaconApiMinimalState{
		slot:                     primitives.Slot(slot),
		blockRoots:               blockRoots,
		finalizedCheckpointEpoch: primitives.Epoch(finalizedEpoch),
		version:                  version,
	}, nil
}

func isActiveAtEpoch(validator *apimiddleware.ValidatorJson, epoch primitives.Epoch) (bool, error) {
	if validator == nil {
		return false, errors.New("validator is nil")
	}

	activationEpoch, err := strconv.ParseUint(validator.ActivationEpoch, 10, 64)
	if err != nil {
		return false, errors.Wrapf(err, "failed to parse validator activation epoch `%s`", validator.ActivationEpoch)
	}

	exitEpoch, err := strconv.ParseUint(validator.ExitEpoch, 10, 64)
	if err != nil {
		return false, errors.Wrapf(err, "failed to parse validator exit epoch `%s`", validator.ExitEpoch)
	}

	return primitives.Epoch(activationEpoch) <= epoch && epoch < primitives.Epoch(exitEpoch), nil
}

func computeActiveEffectiveBalanceAtEpoch(validators []*apimiddleware.ValidatorJson, epoch primitives.Epoch) (uint64, error) {
	var totalEffectiveBalance uint64

	for _, validator := range validators {
		if validator == nil {
			return 0, errors.New("validator is nil")
		}

		active, err := isActiveAtEpoch(validator, epoch)
		if err != nil {
			return 0, errors.Wrapf(err, "failed to retrieve whether validator was active at epoch `%d`", epoch)
		}

		if active {
			validatorEffectiveBalance, err := strconv.ParseUint(validator.EffectiveBalance, 10, 64)
			if err != nil {
				return 0, errors.Wrapf(err, "failed to parse validator effective balance `%s`", validator.EffectiveBalance)
			}

			totalEffectiveBalance += validatorEffectiveBalance
		}
	}

	return totalEffectiveBalance, nil
}

func computeAttestedEffectiveBalance(validators []*apimiddleware.ValidatorJson, correctlyVoted []bool) (uint64, error) {
	var totalEffectiveBalance uint64

	for idx, validator := range validators {
		if validator == nil {
			return 0, errors.New("validator is nil")
		}

		if !validator.Slashed && correctlyVoted[idx] {
			validatorEffectiveBalance, err := strconv.ParseUint(validator.EffectiveBalance, 10, 64)
			if err != nil {
				return 0, errors.Wrapf(err, "failed to parse validator effective balance `%s`", validator.EffectiveBalance)
			}

			totalEffectiveBalance += validatorEffectiveBalance
		}
	}

	return totalEffectiveBalance, nil
}

// def get_attesting_indices(state: BeaconState,
//
//						  data: AttestationData,
//						  bits: Bitlist[MAX_VALIDATORS_PER_COMMITTEE]) -> Set[ValidatorIndex]:
//	"""
//	Return the set of attesting indices corresponding to ``data`` and ``bits``.
//	"""
//	committee = get_beacon_committee(state, data.slot, data.index)
//	return set(index for i, index in enumerate(committee) if bits[i])
func (c beaconApiBeaconChainClient) getAttestingIndices(
	ctx context.Context,
	beaconState *apimiddleware.BeaconStateJson,
	attestationData *ethpb.AttestationData,
	bits bitfield.Bitlist,
) ([]primitives.ValidatorIndex, error) {
	if attestationData == nil {
		return nil, errors.New("attestation data is nil")
	}

	committee, err := c.getBeaconCommittee(ctx, attestationData.Slot, attestationData.CommitteeIndex)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get committee for committee index `%d` and slot `%d`", attestationData.CommitteeIndex, attestationData.Slot)
	}

	if committee == nil {
		return nil, errors.New("committee is nil")
	}

	attestingIndices := make([]primitives.ValidatorIndex, 0, len(committee.Validators))
	for idx, validator := range committee.Validators {
		if bits.BitAt(uint64(idx)) {
			validatorIndex, err := strconv.ParseUint(validator, 10, 64)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to parse validator index `%s`", validator)
			}

			attestingIndices = append(attestingIndices, primitives.ValidatorIndex(validatorIndex))
		}
	}

	return attestingIndices, nil
}

// def get_beacon_committee(state: BeaconState, slot: Slot, index: CommitteeIndex) -> Sequence[ValidatorIndex]:
//
//	"""
//	Return the beacon committee at ``slot`` for ``index``.
//	"""
//	epoch = compute_epoch_at_slot(slot)
//	committees_per_slot = get_committee_count_per_slot(state, epoch)
//	return compute_committee(
//		indices=get_active_validator_indices(state, epoch),
//		seed=get_seed(state, epoch, DOMAIN_BEACON_ATTESTER),
//		index=(slot % SLOTS_PER_EPOCH) * committees_per_slot + index,
//		count=committees_per_slot * SLOTS_PER_EPOCH,
//	)
func (c beaconApiBeaconChainClient) getBeaconCommittee(ctx context.Context, slot primitives.Slot, committeeIndex primitives.CommitteeIndex) (*apimiddleware.CommitteeJson, error) {
	committeeParams := url.Values{}
	committeeParams.Add("epoch", strconv.FormatUint(uint64(slots.ToEpoch(slot)), 10))
	committeeParams.Add("index", strconv.FormatUint(uint64(committeeIndex), 10))
	committeeParams.Add("slot", strconv.FormatUint(uint64(slot), 10))
	committeesRequest := buildURL("/eth/v1/beacon/states/head/committees", committeeParams)

	var stateCommittees apimiddleware.StateCommitteesResponseJson
	if _, err := c.jsonRestHandler.GetRestJsonResponse(ctx, committeesRequest, &stateCommittees); err != nil {
		return nil, errors.Wrapf(err, "failed to query committees for slot `%d`", slot)
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

func convertJsonPendingAttestationsToProto(jsonPendingAttestations []*apimiddleware.PendingAttestationJson) ([]*ethpb.PendingAttestation, error) {
	protoPendingAttestations := make([]*ethpb.PendingAttestation, len(jsonPendingAttestations))

	for idx, jsonPendingAttestation := range jsonPendingAttestations {
		if jsonPendingAttestation == nil {
			return nil, errors.New("pending attestation is nil")
		}

		aggregationBits, err := hexutil.Decode(jsonPendingAttestation.AggregationBits)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to decode aggregation bits `%s`", aggregationBits)
		}

		attestationData, err := convertAttestationDataToProto(jsonPendingAttestation.Data)
		if err != nil {
			return nil, errors.Wrap(err, "failed to convert json attestation data to proto")
		}

		inclusionDelay, err := strconv.ParseUint(jsonPendingAttestation.InclusionDelay, 10, 64)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse pending attestation inclusion delay `%s`", jsonPendingAttestation.InclusionDelay)
		}

		proposerIndex, err := strconv.ParseUint(jsonPendingAttestation.ProposerIndex, 10, 64)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse pending attestation proposer index `%s`", jsonPendingAttestation.ProposerIndex)
		}

		protoPendingAttestations[idx] = &ethpb.PendingAttestation{
			AggregationBits: bitfield.Bitlist(aggregationBits),
			Data:            attestationData,
			InclusionDelay:  primitives.Slot(inclusionDelay),
			ProposerIndex:   primitives.ValidatorIndex(proposerIndex),
		}
	}

	return protoPendingAttestations, nil
}

func convertValidatorsToPrecomputeValidators(
	validators []*apimiddleware.ValidatorJson,
	currentEpoch primitives.Epoch,
	currentEffectiveBalances []uint64,
	correctlyVotedSource []bool,
	correctlyVotedTarget []bool,
	correctlyVotedHead []bool,
	inclusionDistances []primitives.Slot,
) ([]*precompute.Validator, error) {
	precomputeValidators := make([]*precompute.Validator, len(validators))
	for idx := range precomputeValidators {
		validator := validators[idx]

		var prevEpoch primitives.Epoch
		if currentEpoch > 0 {
			prevEpoch = currentEpoch - 1
		}

		isActivePrevEpoch, err := isActiveAtEpoch(validator, prevEpoch)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to retrieve whether validator was active at previous epoch `%d`", prevEpoch)
		}

		withdrawableEpoch, err := strconv.ParseUint(validator.WithdrawableEpoch, 10, 64)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse validator withdrawable epoch `%s`", validator.WithdrawableEpoch)
		}

		precomputeValidators[idx] = &precompute.Validator{
			IsSlashed:                    validator.Slashed,
			CurrentEpochEffectiveBalance: currentEffectiveBalances[idx],
			IsPrevEpochAttester:          correctlyVotedSource[idx],
			IsPrevEpochSourceAttester:    correctlyVotedSource[idx],
			IsPrevEpochTargetAttester:    correctlyVotedTarget[idx],
			IsPrevEpochHeadAttester:      correctlyVotedHead[idx],
			InclusionDistance:            inclusionDistances[idx],
			IsActivePrevEpoch:            isActivePrevEpoch,
			IsWithdrawableCurrentEpoch:   currentEpoch >= primitives.Epoch(withdrawableEpoch),
		}
	}

	return precomputeValidators, nil
}

func (c beaconApiBeaconChainClient) getPhase0ValidatorPerformance(
	ctx context.Context,
	beaconState apimiddleware.BeaconStateJson,
	version string,
	pubkeys [][]byte,
	validatorPubkeyToIndex map[string]primitives.ValidatorIndex,
	validatorIndexToArrayIndex map[primitives.ValidatorIndex]int,
	currentEffectiveBalances []uint64,
	validators []*apimiddleware.ValidatorJson,
	balancesBeforeEpochTransition []uint64,
) (*ethpb.ValidatorPerformanceResponse, error) {
	minimalState, err := NewBeaconApiMinimalState(beaconState, version)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create beacon api minimal state")
	}

	currentSlot, err := strconv.ParseUint(beaconState.Slot, 10, 64)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse slot `%s`", beaconState.Slot)
	}

	currentEpoch := slots.ToEpoch(primitives.Slot(currentSlot))

	protoPreviousPendingAttestations, err := convertJsonPendingAttestationsToProto(beaconState.PreviousEpochAttestations)
	if err != nil {
		return nil, errors.Wrap(err, "failed to convert json pending attestations to proto")
	}

	correctlyVotedSource := make([]bool, len(validators))
	correctlyVotedTarget := make([]bool, len(validators))
	correctlyVotedHead := make([]bool, len(validators))
	correctlyVotedSourceGlobal := make([]bool, len(beaconState.Validators))
	correctlyVotedTargetGlobal := make([]bool, len(beaconState.Validators))
	correctlyVotedHeadGlobal := make([]bool, len(beaconState.Validators))
	inclusionDistances := make([]primitives.Slot, len(validators))

	for _, pendingAttestation := range protoPreviousPendingAttestations {
		isPrevEpochAttester, isPrevEpochTargetAttester, isPrevEpochHeadAttester, err := precompute.AttestedPrevEpoch(minimalState, pendingAttestation)
		if err != nil {
			return nil, errors.Wrap(err, "failed to retrieve whether attestation attested in previous epoch")
		}

		attestingIndices, err := c.getAttestingIndices(ctx, &beaconState, pendingAttestation.Data, pendingAttestation.AggregationBits)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get attesting indices")
		}

		for _, validatorIndex := range attestingIndices {
			correctlyVotedSourceGlobal[validatorIndex] = isPrevEpochAttester
			correctlyVotedTargetGlobal[validatorIndex] = isPrevEpochTargetAttester
			correctlyVotedHeadGlobal[validatorIndex] = isPrevEpochHeadAttester

			if validatorArrayIndex, ok := validatorIndexToArrayIndex[validatorIndex]; ok {
				correctlyVotedSource[validatorArrayIndex] = isPrevEpochAttester
				correctlyVotedTarget[validatorArrayIndex] = isPrevEpochTargetAttester
				correctlyVotedHead[validatorArrayIndex] = isPrevEpochHeadAttester
				inclusionDistances[validatorArrayIndex] = pendingAttestation.InclusionDelay
			}
		}
	}

	precomputeValidators, err := convertValidatorsToPrecomputeValidators(
		validators,
		currentEpoch,
		currentEffectiveBalances,
		correctlyVotedSource,
		correctlyVotedTarget,
		correctlyVotedHead,
		inclusionDistances,
	)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to convert json validators to precompute validators")
	}

	currentActiveEffectiveBalance, err := computeActiveEffectiveBalanceAtEpoch(beaconState.Validators, currentEpoch)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to compute active effective balance at epoch `%d`", currentEpoch)
	}

	prevEpochSourceAttestedEffectiveBalance, err := computeAttestedEffectiveBalance(beaconState.Validators, correctlyVotedSourceGlobal)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to compute source attested effective balance at epoch `%d`", currentEpoch)
	}

	prevEpochTargetAttestedEffectiveBalance, err := computeAttestedEffectiveBalance(beaconState.Validators, correctlyVotedTargetGlobal)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to compute target attested effective balance at epoch `%d`", currentEpoch)
	}

	prevEpochHeadAttestedEffectiveBalance, err := computeAttestedEffectiveBalance(beaconState.Validators, correctlyVotedHeadGlobal)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to compute head attested effective balance at epoch `%d`", currentEpoch)
	}

	precomputeBalance := &precompute.Balance{
		PrevEpochAttested:       prevEpochSourceAttestedEffectiveBalance,
		PrevEpochTargetAttested: prevEpochTargetAttestedEffectiveBalance,
		PrevEpochHeadAttested:   prevEpochHeadAttestedEffectiveBalance,
		ActiveCurrentEpoch:      currentActiveEffectiveBalance,
	}

	rewards, penalties, err := precompute.AttestationsDelta(minimalState, precomputeBalance, precomputeValidators)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get attestation rewards and penalties")
	}

	balancesAfterEpochTransition := make([]uint64, len(pubkeys))
	for idx := range validators {
		balancesAfterEpochTransition[idx] = balancesBeforeEpochTransition[idx] + rewards[idx] - penalties[idx]
	}

	validatorPerformanceResponse := &ethpb.ValidatorPerformanceResponse{
		CurrentEffectiveBalances:      currentEffectiveBalances,
		CorrectlyVotedSource:          correctlyVotedSource,
		CorrectlyVotedTarget:          correctlyVotedTarget,
		CorrectlyVotedHead:            correctlyVotedHead,
		BalancesBeforeEpochTransition: balancesBeforeEpochTransition,
		BalancesAfterEpochTransition:  balancesAfterEpochTransition, // TODO (pavignol): Correctly query the balances before epoch transition
		MissingValidators:             [][]byte{},                   // TODO (pavignol): Figure out which validators are missing
		PublicKeys:                    pubkeys,
	}

	marshalledRest, err := json.Marshal(validatorPerformanceResponse)
	if err != nil {
		return nil, err
	}

	grpcResponse, err := c.fallbackClient.GetValidatorPerformance(ctx, &ethpb.ValidatorPerformanceRequest{
		PublicKeys: pubkeys,
	})
	if err != nil {
		return nil, err
	}

	marshalledGrpc, err := json.Marshal(grpcResponse)
	if err != nil {
		return nil, err
	}

	log.Errorf("*****************phase0 GRPC: %s", string(marshalledGrpc))
	log.Errorf("*****************phase0 REST: %s", string(marshalledRest))

	return validatorPerformanceResponse, nil
}

func (c beaconApiBeaconChainClient) getAltairValidatorPerformance(
	beaconState minimalBeaconStateAltairJson,
	version string,
	pubkeys [][]byte,
	validatorPubkeyToIndex map[string]primitives.ValidatorIndex,
	validatorIndexToArrayIndex map[primitives.ValidatorIndex]int,
	currentEffectiveBalances []uint64,
	validators []*apimiddleware.ValidatorJson,
) (*ethpb.ValidatorPerformanceResponse, error) {
	minimalState, err := NewBeaconApiMinimalAltairState(beaconState, version)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create beacon api minimal state")
	}

	currentEpoch := slots.ToEpoch(minimalState.Slot())

	cfg := params.BeaconConfig()

	correctlyVotedSource := make([]bool, len(validators))
	correctlyVotedTarget := make([]bool, len(validators))
	correctlyVotedHead := make([]bool, len(validators))
	correctlyVotedSourceGlobal := make([]bool, len(beaconState.validators))
	correctlyVotedTargetGlobal := make([]bool, len(beaconState.validators))
	correctlyVotedHeadGlobal := make([]bool, len(beaconState.validators))
	balancesBeforeEpochTransition := make([]uint64, len(validators))

	inactivityScores := make([]uint64, len(validators))

	for validatorIndex, validator := range beaconState.validators {
		if uint64(validatorIndex) >= uint64(len(beaconState.previousEpochParticipation)) {
			return nil, errors.Errorf("validator index `%d` is too big for length `%d` of the previous epoch participations", validatorIndex, len(beaconState.previousEpochParticipation))
		}

		previousEpochParticipation, err := strconv.ParseUint(beaconState.previousEpochParticipation[validatorIndex], 10, 8)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse previous epoch participation `%s`", beaconState.previousEpochParticipation[validatorIndex])
		}

		activePrevEpoch, err := isActiveAtEpoch(validator, beacontime.PrevEpoch(minimalState))
		if err != nil {
			return nil, errors.Wrapf(err, "failed to retrieve whether validator was active at epoch `%d`", currentEpoch)
		}

		validatorArrayIndex, isOurValidator := validatorIndexToArrayIndex[primitives.ValidatorIndex(validatorIndex)]

		if activePrevEpoch {
			hasSourceFlag, err := altair.HasValidatorFlag(byte(previousEpochParticipation), cfg.TimelySourceFlagIndex)
			if err != nil {
				return nil, errors.Wrap(err, "failed to get source flag from previous epoch participation")
			}
			correctlyVotedSourceGlobal[validatorIndex] = hasSourceFlag

			hasTargetFlag, err := altair.HasValidatorFlag(byte(previousEpochParticipation), cfg.TimelyTargetFlagIndex)
			if err != nil {
				return nil, errors.Wrap(err, "failed to get target flag from previous epoch participation")
			}
			correctlyVotedTargetGlobal[validatorIndex] = hasTargetFlag

			hasHeadFlag, err := altair.HasValidatorFlag(byte(previousEpochParticipation), cfg.TimelyHeadFlagIndex)
			if err != nil {
				return nil, errors.Wrap(err, "failed to get head flag from previous epoch participation")
			}
			correctlyVotedHeadGlobal[validatorIndex] = hasHeadFlag

			if isOurValidator {
				correctlyVotedSource[validatorArrayIndex] = correctlyVotedSourceGlobal[validatorIndex]
				correctlyVotedTarget[validatorArrayIndex] = correctlyVotedSourceGlobal[validatorIndex]
				correctlyVotedHead[validatorArrayIndex] = correctlyVotedTargetGlobal[validatorIndex]
			}
		}

		if isOurValidator {
			balance, err := strconv.ParseUint(beaconState.balances[validatorIndex], 10, 64)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to parse balance `%s`", beaconState.balances[validatorIndex])
			}

			balancesBeforeEpochTransition[validatorArrayIndex] = balance

			inactivityScore, err := strconv.ParseUint(beaconState.inactivityScores[validatorIndex], 10, 64)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to parse inactivity score `%s`", beaconState.inactivityScores[validatorIndex])
			}

			inactivityScores[validatorArrayIndex] = inactivityScore
		}
	}

	inclusionDistances := make([]primitives.Slot, len(validators))

	precomputeValidators, err := convertValidatorsToPrecomputeValidators(
		validators,
		currentEpoch,
		currentEffectiveBalances,
		correctlyVotedSource,
		correctlyVotedTarget,
		correctlyVotedHead,
		inclusionDistances,
	)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to convert json validators to precompute validators")
	}

	currentActiveEffectiveBalance, err := computeActiveEffectiveBalanceAtEpoch(beaconState.validators, currentEpoch)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to compute active effective balance at epoch `%d`", currentEpoch)
	}

	prevEpochSourceAttestedEffectiveBalance, err := computeAttestedEffectiveBalance(beaconState.validators, correctlyVotedSourceGlobal)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to compute source attested effective balance at epoch `%d`", currentEpoch)
	}

	prevEpochTargetAttestedEffectiveBalance, err := computeAttestedEffectiveBalance(beaconState.validators, correctlyVotedTargetGlobal)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to compute target attested effective balance at epoch `%d`", currentEpoch)
	}

	prevEpochHeadAttestedEffectiveBalance, err := computeAttestedEffectiveBalance(beaconState.validators, correctlyVotedHeadGlobal)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to compute head attested effective balance at epoch `%d`", currentEpoch)
	}

	precomputeBalance := &precompute.Balance{
		PrevEpochAttested:       prevEpochSourceAttestedEffectiveBalance,
		PrevEpochTargetAttested: prevEpochTargetAttestedEffectiveBalance,
		PrevEpochHeadAttested:   prevEpochHeadAttestedEffectiveBalance,
		ActiveCurrentEpoch:      currentActiveEffectiveBalance,
	}

	rewards, penalties, err := altair.AttestationsDelta(minimalState, precomputeBalance, precomputeValidators)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get attestation rewards and penalties")
	}

	balancesAfterEpochTransition := make([]uint64, len(pubkeys))
	for idx := range validators {
		balancesAfterEpochTransition[idx] = balancesBeforeEpochTransition[idx] + rewards[idx] - penalties[idx]
	}

	validatorPerformanceResponse := &ethpb.ValidatorPerformanceResponse{
		CurrentEffectiveBalances:      currentEffectiveBalances,
		CorrectlyVotedSource:          correctlyVotedSource,
		CorrectlyVotedTarget:          correctlyVotedTarget,
		CorrectlyVotedHead:            correctlyVotedHead,
		BalancesBeforeEpochTransition: balancesBeforeEpochTransition,
		BalancesAfterEpochTransition:  balancesAfterEpochTransition, // TODO (pavignol): Correctly query the balances before epoch transition
		MissingValidators:             [][]byte{},                   // TODO (pavignol): Figure out which validators are missing
		PublicKeys:                    pubkeys,
		InactivityScores:              inactivityScores,
	}

	marshalledRest, err := json.Marshal(validatorPerformanceResponse)
	if err != nil {
		return nil, err
	}

	grpcResponse, err := c.fallbackClient.GetValidatorPerformance(context.Background(), &ethpb.ValidatorPerformanceRequest{
		PublicKeys: pubkeys,
	})
	if err != nil {
		return nil, err
	}

	marshalledGrpc, err := json.Marshal(grpcResponse)
	if err != nil {
		return nil, err
	}

	log.Errorf("*****************%s GRPC: %s", version, string(marshalledGrpc))
	log.Errorf("*****************%s REST: %s", version, string(marshalledRest))

	return validatorPerformanceResponse, nil
}

func (c beaconApiMinimalState) BlockRootAtIndex(idx uint64) ([]byte, error) {
	if idx >= uint64(len(c.blockRoots)) {
		return nil, errors.Errorf("block root index `%d` is too big for BlockRoots array", idx)
	}

	return c.blockRoots[idx], nil
}

func (c beaconApiMinimalState) BlockRoots() [][]byte {
	return c.blockRoots
}

func (c beaconApiMinimalState) Slot() primitives.Slot {
	return c.slot
}

func (c beaconApiMinimalState) FinalizedCheckpointEpoch() primitives.Epoch {
	return c.finalizedCheckpointEpoch
}

func (c beaconApiMinimalState) ProportionalSlashingMultiplier() (uint64, error) {
	switch c.version {
	case "bellatrix", "capella":
		return params.BeaconConfig().ProportionalSlashingMultiplierBellatrix, nil
	case "altair":
		return params.BeaconConfig().ProportionalSlashingMultiplierAltair, nil
	case "phase0":
		return params.BeaconConfig().ProportionalSlashingMultiplier, nil
	}
	return 0, errors.Errorf("unsupported version `%s` for ProportionalSlashingMultiplier()", c.version)
}

func (c beaconApiMinimalState) InactivityPenaltyQuotient() (uint64, error) {
	switch c.version {
	case "bellatrix", "capella":
		return params.BeaconConfig().InactivityPenaltyQuotientBellatrix, nil
	case "altair":
		return params.BeaconConfig().InactivityPenaltyQuotientAltair, nil
	case "phase0":
		return params.BeaconConfig().InactivityPenaltyQuotient, nil
	}
	return 0, errors.Errorf("unsupported version `%s` for InactivityPenaltyQuotient()", c.version)
}
