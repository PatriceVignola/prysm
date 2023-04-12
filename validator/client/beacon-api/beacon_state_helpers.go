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
	numValidators            int
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

func (c beaconApiMinimalState) NumValidators() int {
	return c.numValidators
}

func newBeaconApiMinimalState(
	jsonSlot string,
	jsonBlockRoots []string,
	jsonFinalizedCheckpoint *apimiddleware.CheckpointJson,
	numValidators int,
	version string,
) (*beaconApiMinimalState, error) {
	slot, err := strconv.ParseUint(jsonSlot, 10, 64)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse slot `%s`", jsonSlot)
	}

	blockRoots := make([][]byte, len(jsonBlockRoots))
	for idx, jsonBlockRoot := range jsonBlockRoots {
		blockRoot, err := hexutil.Decode(jsonBlockRoot)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to decode block root `%s`", jsonBlockRoot)
		}

		blockRoots[idx] = blockRoot
	}

	if jsonFinalizedCheckpoint == nil {
		return nil, errors.New("finalized checkpoint is nil")
	}

	finalizedEpoch, err := strconv.ParseUint(jsonFinalizedCheckpoint.Epoch, 10, 64)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse finalized epoch `%s`", jsonFinalizedCheckpoint.Epoch)
	}

	return &beaconApiMinimalState{
		slot:                     primitives.Slot(slot),
		blockRoots:               blockRoots,
		finalizedCheckpointEpoch: primitives.Epoch(finalizedEpoch),
		version:                  version,
		numValidators:            numValidators,
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
	proposerIndices []primitives.ValidatorIndex,
) ([]*precompute.Validator, error) {
	precomputeValidators := make([]*precompute.Validator, len(validators))
	for idx, validator := range validators {
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
			IsActivePrevEpoch:            isActivePrevEpoch,
			IsWithdrawableCurrentEpoch:   currentEpoch >= primitives.Epoch(withdrawableEpoch),
		}

		if inclusionDistances != nil {
			precomputeValidators[idx].InclusionDistance = inclusionDistances[idx]
		}

		if proposerIndices != nil {
			precomputeValidators[idx].ProposerIndex = proposerIndices[idx]
		}
	}

	return precomputeValidators, nil
}

func (c beaconApiBeaconChainClient) getPhase0ValidatorPerformance(
	ctx context.Context,
	beaconState apimiddleware.BeaconStateJson,
	version string,
	pubkeys [][]byte,
) (*ethpb.ValidatorPerformanceResponse, error) {
	minimalState, err := newBeaconApiMinimalState(beaconState.Slot, beaconState.BlockRoots, beaconState.FinalizedCheckpoint, len(beaconState.Validators), version)
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

	validatorPubkeyToArrayIndex := make(map[string]int)
	for idx, pubkey := range pubkeys {
		pubkeyString := hexutil.Encode(pubkey)
		validatorPubkeyToArrayIndex[pubkeyString] = idx
	}

	activePubkeys := make([][]byte, 0)
	inactivePubkeys := make([][]byte, 0)

	for _, validator := range beaconState.Validators {
		if pubkeyIndex, ok := validatorPubkeyToArrayIndex[validator.PublicKey]; ok {
			activationEpoch, err := strconv.ParseUint(validator.ActivationEpoch, 10, 64)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to parse activation epoch `%s`", validator.ActivationEpoch)
			}

			exitEpoch, err := strconv.ParseUint(validator.ExitEpoch, 10, 64)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to parse exit epoch `%s`", validator.ExitEpoch)
			}

			isActive := primitives.Epoch(activationEpoch) <= currentEpoch && currentEpoch < primitives.Epoch(exitEpoch)
			pubkey := pubkeys[pubkeyIndex]

			if isActive {
				validatorPubkeyToArrayIndex[validator.PublicKey] = len(activePubkeys)
				activePubkeys = append(activePubkeys, pubkey)
			} else {
				inactivePubkeys = append(inactivePubkeys, pubkey)
				delete(validatorPubkeyToArrayIndex, validator.PublicKey)
			}
		}
	}

	correctlyVotedSource := make([]bool, len(activePubkeys))
	correctlyVotedTarget := make([]bool, len(activePubkeys))
	correctlyVotedHead := make([]bool, len(activePubkeys))
	currentEffectiveBalances := make([]uint64, len(activePubkeys))
	correctlyVotedSourceGlobal := make([]bool, len(beaconState.Validators))
	correctlyVotedTargetGlobal := make([]bool, len(beaconState.Validators))
	correctlyVotedHeadGlobal := make([]bool, len(beaconState.Validators))
	proposerIndicesGlobal := make([]primitives.ValidatorIndex, len(beaconState.Validators))
	inclusionDistancesGlobal := make([]primitives.Slot, len(beaconState.Validators))
	currentEffectiveBalancesGlobal := make([]uint64, len(beaconState.Validators))

	for _, pendingAttestation := range protoPreviousPendingAttestations {
		isPrevEpochAttester, isPrevEpochTargetAttester, isPrevEpochHeadAttester, err := precompute.AttestedPrevEpoch(minimalState, pendingAttestation)
		if err != nil {
			return nil, errors.Wrap(err, "failed to retrieve whether attestation attested in previous epoch")
		}

		attestingIndices, err := c.getAttestingIndices(ctx, pendingAttestation.Data, pendingAttestation.AggregationBits)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get attesting indices")
		}

		for _, validatorIndex := range attestingIndices {
			correctlyVotedSourceGlobal[validatorIndex] = isPrevEpochAttester
			correctlyVotedTargetGlobal[validatorIndex] = isPrevEpochTargetAttester
			correctlyVotedHeadGlobal[validatorIndex] = isPrevEpochHeadAttester
			proposerIndicesGlobal[validatorIndex] = pendingAttestation.ProposerIndex
			inclusionDistancesGlobal[validatorIndex] = pendingAttestation.InclusionDelay

			pubkey := beaconState.Validators[validatorIndex].PublicKey
			if validatorArrayIndex, ok := validatorPubkeyToArrayIndex[pubkey]; ok {
				correctlyVotedSource[validatorArrayIndex] = isPrevEpochAttester
				correctlyVotedTarget[validatorArrayIndex] = isPrevEpochTargetAttester
				correctlyVotedHead[validatorArrayIndex] = isPrevEpochHeadAttester
			}
		}
	}

	for validatorIndex, validator := range beaconState.Validators {
		effectiveBalance, err := strconv.ParseUint(validator.EffectiveBalance, 10, 64)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse effective balance `%s`", validator.EffectiveBalance)
		}

		currentEffectiveBalancesGlobal[validatorIndex] = effectiveBalance

		if validatorArrayIndex, ok := validatorPubkeyToArrayIndex[validator.PublicKey]; ok {
			currentEffectiveBalances[validatorArrayIndex] = effectiveBalance
		}
	}

	precomputeValidatorsGlobal, err := convertValidatorsToPrecomputeValidators(
		beaconState.Validators,
		currentEpoch,
		currentEffectiveBalancesGlobal,
		correctlyVotedSourceGlobal,
		correctlyVotedTargetGlobal,
		correctlyVotedHeadGlobal,
		inclusionDistancesGlobal,
		proposerIndicesGlobal,
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

	attestationRewardsGlobal, attestationPenaltiesGlobal, err := precompute.AttestationsDelta(minimalState, precomputeBalance, precomputeValidatorsGlobal)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get attestation rewards and penalties")
	}

	proposerRewardsGlobal, err := precompute.ProposersDelta(minimalState, precomputeBalance, precomputeValidatorsGlobal)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get proposer rewards and penalties")
	}

	// We retrieved rewards and penalties for the entire validator set, so we need to extract them for only the ones we care about
	balancesBeforeEpochTransition := make([]uint64, len(activePubkeys))
	balancesAfterEpochTransition := make([]uint64, len(activePubkeys))
	for validatorIndex, validator := range beaconState.Validators {
		if validatorArrayIndex, ok := validatorPubkeyToArrayIndex[validator.PublicKey]; ok {
			balanceBeforeTransition, err := strconv.ParseUint(beaconState.Balances[validatorIndex], 10, 64)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to parse balance `%s`", beaconState.Balances[validatorIndex])
			}

			balancesBeforeEpochTransition[validatorArrayIndex] = balanceBeforeTransition

			rewards := attestationRewardsGlobal[validatorIndex] + proposerRewardsGlobal[validatorIndex]
			penalties := attestationPenaltiesGlobal[validatorIndex]
			balancesAfterEpochTransition[validatorArrayIndex] = balanceBeforeTransition + rewards - penalties
		}
	}

	validatorPerformanceResponse := &ethpb.ValidatorPerformanceResponse{
		CurrentEffectiveBalances:      currentEffectiveBalances,
		CorrectlyVotedSource:          correctlyVotedSource,
		CorrectlyVotedTarget:          correctlyVotedTarget,
		CorrectlyVotedHead:            correctlyVotedHead,
		BalancesBeforeEpochTransition: balancesBeforeEpochTransition,
		BalancesAfterEpochTransition:  balancesAfterEpochTransition,
		MissingValidators:             inactivePubkeys,
		PublicKeys:                    activePubkeys,
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
) (*ethpb.ValidatorPerformanceResponse, error) {
	minimalState, err := newBeaconApiMinimalState(beaconState.slot, beaconState.blockRoots, beaconState.finalizedCheckpoint, len(beaconState.validators), version)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create beacon api minimal state")
	}

	currentEpoch := slots.ToEpoch(minimalState.Slot())

	validatorPubkeyToArrayIndex := make(map[string]int)
	for idx, pubkey := range pubkeys {
		pubkeyString := hexutil.Encode(pubkey)
		validatorPubkeyToArrayIndex[pubkeyString] = idx
	}

	activePubkeys := make([][]byte, 0)
	inactivePubkeys := make([][]byte, 0)

	for _, validator := range beaconState.validators {
		if pubkeyIndex, ok := validatorPubkeyToArrayIndex[validator.PublicKey]; ok {
			activationEpoch, err := strconv.ParseUint(validator.ActivationEpoch, 10, 64)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to parse activation epoch `%s`", validator.ActivationEpoch)
			}

			exitEpoch, err := strconv.ParseUint(validator.ExitEpoch, 10, 64)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to parse exit epoch `%s`", validator.ExitEpoch)
			}

			isActive := primitives.Epoch(activationEpoch) <= currentEpoch && currentEpoch < primitives.Epoch(exitEpoch)
			pubkey := pubkeys[pubkeyIndex]

			if isActive {
				validatorPubkeyToArrayIndex[validator.PublicKey] = len(activePubkeys)
				activePubkeys = append(activePubkeys, pubkey)
			} else {
				inactivePubkeys = append(inactivePubkeys, pubkey)
				delete(validatorPubkeyToArrayIndex, validator.PublicKey)
			}
		}
	}

	cfg := params.BeaconConfig()

	correctlyVotedSource := make([]bool, len(activePubkeys))
	correctlyVotedTarget := make([]bool, len(activePubkeys))
	correctlyVotedHead := make([]bool, len(activePubkeys))
	correctlyVotedSourceGlobal := make([]bool, len(beaconState.validators))
	correctlyVotedTargetGlobal := make([]bool, len(beaconState.validators))
	correctlyVotedHeadGlobal := make([]bool, len(beaconState.validators))
	balancesBeforeEpochTransition := make([]uint64, len(activePubkeys))
	inactivityScores := make([]uint64, len(activePubkeys))
	currentEffectiveBalances := make([]uint64, len(activePubkeys))

	validators := make([]*apimiddleware.ValidatorJson, len(activePubkeys))
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

		validatorArrayIndex, isOurValidator := validatorPubkeyToArrayIndex[validator.PublicKey]

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

			currentEffectiveBalance, err := strconv.ParseUint(validator.EffectiveBalance, 10, 64)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to parse current effective balance `%s`", validator.EffectiveBalance)
			}
			currentEffectiveBalances[validatorArrayIndex] = currentEffectiveBalance

			validators[validatorArrayIndex] = validator
		}
	}

	precomputeValidators, err := convertValidatorsToPrecomputeValidators(
		validators,
		currentEpoch,
		currentEffectiveBalances,
		correctlyVotedSource,
		correctlyVotedTarget,
		correctlyVotedHead,
		nil,
		nil,
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

	balancesAfterEpochTransition := make([]uint64, len(activePubkeys))
	for idx := range validators {
		balancesAfterEpochTransition[idx] = balancesBeforeEpochTransition[idx] + rewards[idx] - penalties[idx]
	}

	validatorPerformanceResponse := &ethpb.ValidatorPerformanceResponse{
		CurrentEffectiveBalances:      currentEffectiveBalances,
		CorrectlyVotedSource:          correctlyVotedSource,
		CorrectlyVotedTarget:          correctlyVotedTarget,
		CorrectlyVotedHead:            correctlyVotedHead,
		BalancesBeforeEpochTransition: balancesBeforeEpochTransition,
		BalancesAfterEpochTransition:  balancesAfterEpochTransition,
		MissingValidators:             inactivePubkeys,
		PublicKeys:                    activePubkeys,
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
