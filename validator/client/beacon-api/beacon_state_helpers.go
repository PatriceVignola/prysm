package beacon_api

import (
	"context"
	"math"
	"net/url"
	"strconv"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/pkg/errors"
	"github.com/prysmaticlabs/go-bitfield"
	"github.com/prysmaticlabs/prysm/v4/beacon-chain/core/altair"
	"github.com/prysmaticlabs/prysm/v4/beacon-chain/core/helpers"
	"github.com/prysmaticlabs/prysm/v4/beacon-chain/rpc/apimiddleware"
	"github.com/prysmaticlabs/prysm/v4/config/params"
	"github.com/prysmaticlabs/prysm/v4/consensus-types/primitives"
	mathprysm "github.com/prysmaticlabs/prysm/v4/math"
	"github.com/prysmaticlabs/prysm/v4/time/slots"
)

// def get_block_root(state: BeaconState, epoch: Epoch) -> Root:
//
//	"""
//	Return the block root at the start of a recent ``epoch``.
//	"""
//	return get_block_root_at_slot(state, compute_start_slot_at_epoch(epoch))
func getBlockRoot(beaconState *apimiddleware.BeaconStateJson, epoch primitives.Epoch) (string, error) {
	slot, err := slots.EpochStart(epoch)
	if err != nil {
		return "", err
	}
	return getBlockRootAtSlot(beaconState, slot)
}

// def get_block_root_at_slot(state: BeaconState, slot: Slot) -> Root:
//
//	"""
//	Return the block root at a recent ``slot``.
//	"""
//	assert slot < state.slot <= slot + SLOTS_PER_HISTORICAL_ROOT
//	return state.block_roots[slot % SLOTS_PER_HISTORICAL_ROOT]
func getBlockRootAtSlot(beaconState *apimiddleware.BeaconStateJson, slot primitives.Slot) (string, error) {
	if beaconState == nil {
		return "", errors.New("beacon state is nil")
	}

	if math.MaxUint64-slot < params.BeaconConfig().SlotsPerHistoricalRoot {
		return "", errors.New("slot overflows uint64")
	}

	stateSlot, err := strconv.ParseUint(beaconState.Slot, 10, 64)
	if err != nil {
		return "", errors.Wrapf(err, "failed to parse slot `%s`", beaconState.Slot)
	}

	if slot >= primitives.Slot(stateSlot) || primitives.Slot(stateSlot) > slot+params.BeaconConfig().SlotsPerHistoricalRoot {
		return "", errors.Errorf("slot %d out of bounds", slot)
	}

	blockRootIndex := int(slot % params.BeaconConfig().SlotsPerHistoricalRoot)
	if blockRootIndex >= len(beaconState.BlockRoots) {
		return "", errors.Errorf("block root index `%d` is out of bounds", blockRootIndex)
	}

	return beaconState.BlockRoots[blockRootIndex], nil
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

func AttestationsDelta(
	beaconState *apimiddleware.BeaconStateJson,
	vals []*apimiddleware.ValidatorJson,
	currentEpochTotalActiveEffectiveBalance uint64,
	prevEpochSourceAttestedEffectiveBalance uint64,
	prevEpochHeadAttestedEffectiveBalance uint64,
	prevEpochTargetAttestedEffectiveBalance uint64,
	correctlyVotedSource []bool,
	correctlyVotedTarget []bool,
	correctlyVotedHead []bool,
	inactivityScores []uint64,
) ([]uint64, []uint64, error) {
	if beaconState == nil {
		return nil, nil, errors.New("beacon state is nil")
	}

	rewards := make([]uint64, len(vals))
	penalties := make([]uint64, len(vals))

	cfg := params.BeaconConfig()

	currentSlot, err := strconv.ParseUint(beaconState.Slot, 10, 64)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to parse beacon state slot `%s`", beaconState.Slot)
	}

	currentEpoch := slots.ToEpoch(primitives.Slot(currentSlot))
	var prevEpoch primitives.Epoch
	if currentEpoch > 0 {
		prevEpoch = currentEpoch - 1
	}

	if beaconState.FinalizedCheckpoint != nil {
		return nil, nil, errors.New("beacon state finalized checkpoint is nil")
	}

	finalizedEpoch, err := strconv.ParseUint(beaconState.FinalizedCheckpoint.Epoch, 10, 64)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to parse finalized checkpoint epoch `%s`", beaconState.FinalizedCheckpoint.Epoch)
	}

	increment := cfg.EffectiveBalanceIncrement
	factor := cfg.BaseRewardFactor
	baseRewardMultiplier := increment * factor / mathprysm.CachedSquareRoot(currentEpochTotalActiveEffectiveBalance)
	leak := helpers.IsInInactivityLeak(prevEpoch, primitives.Epoch(finalizedEpoch))

	// Modified in Altair and Bellatrix.
	inactivityPenaltyQuotient, err := inactivityPenaltyQuotient(beaconState)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to get inactivity penalty quotient")
	}
	inactivityDenominator := cfg.InactivityScoreBias * inactivityPenaltyQuotient

	for i, v := range vals {
		rewards[i], penalties[i], err = attestationDelta(
			v,
			baseRewardMultiplier,
			inactivityDenominator,
			leak,
			currentEpoch,
			currentEpochTotalActiveEffectiveBalance,
			prevEpochSourceAttestedEffectiveBalance,
			prevEpochTargetAttestedEffectiveBalance,
			prevEpochHeadAttestedEffectiveBalance,
			correctlyVotedSource[i],
			correctlyVotedTarget[i],
			correctlyVotedHead[i],
			inactivityScores[i],
		)
		if err != nil {
			return nil, nil, err
		}
	}

	return rewards, penalties, nil
}

func attestationDelta(
	val *apimiddleware.ValidatorJson,
	baseRewardMultiplier uint64,
	inactivityDenominator uint64,
	inactivityLeak bool,
	currentEpoch primitives.Epoch,
	currentEpochTotalActiveEffectiveBalance uint64,
	prevEpochSourceAttestedEffectiveBalance uint64,
	prevEpochTargetAttestedEffectiveBalance uint64,
	prevEpochHeadAttestedEffectiveBalance uint64,
	correctlyVotedSource bool,
	correctlyVotedTarget bool,
	correctlyVotedHead bool,
	inactivityScore uint64,
) (uint64, uint64, error) {
	if val == nil {
		return 0, 0, errors.New("validator is nil")
	}

	withdrawableEpoch, err := strconv.ParseUint(val.WithdrawableEpoch, 10, 64)
	if err != nil {
		return 0, 0, errors.Wrapf(err, "failed to parse validator withdrawable epoch `%s`", val.WithdrawableEpoch)
	}

	var prevEpoch primitives.Epoch
	if currentEpoch > 0 {
		prevEpoch = currentEpoch - 1
	}

	isActivePrevEpoch, err := isActiveAtEpoch(val, prevEpoch)
	if err != nil {
		return 0, 0, errors.Wrapf(err, "failed to retrieve whether validator was active at previous epoch `%d`", prevEpoch)
	}

	isWithdrawableCurrentEpoch := currentEpoch >= primitives.Epoch(withdrawableEpoch)

	eligible := isActivePrevEpoch || (val.Slashed && !isWithdrawableCurrentEpoch)
	// Per spec `currentEpochTotalActiveEffectiveBalance` can't be 0 to process attestation delta.
	if !eligible || currentEpochTotalActiveEffectiveBalance == 0 {
		return 0, 0, nil
	}

	effectiveBalance, err := strconv.ParseUint(val.EffectiveBalance, 10, 64)
	if err != nil {
		return 0, 0, errors.Wrapf(err, "failed to parse validator effective balance `%s`", val.EffectiveBalance)
	}

	cfg := params.BeaconConfig()
	increment := cfg.EffectiveBalanceIncrement
	baseReward := (effectiveBalance / increment) * baseRewardMultiplier
	activeIncrement := currentEpochTotalActiveEffectiveBalance / increment

	weightDenominator := cfg.WeightDenominator
	srcWeight := cfg.TimelySourceWeight
	tgtWeight := cfg.TimelyTargetWeight
	headWeight := cfg.TimelyHeadWeight
	var reward uint64
	var penalty uint64
	// Process source reward / penalty
	if correctlyVotedSource && !val.Slashed {
		if !inactivityLeak {
			n := baseReward * srcWeight * (prevEpochSourceAttestedEffectiveBalance / increment)
			reward += n / (activeIncrement * weightDenominator)
		}
	} else {
		penalty += baseReward * srcWeight / weightDenominator
	}

	// Process target reward / penalty
	if correctlyVotedTarget && !val.Slashed {
		if !inactivityLeak {
			n := baseReward * tgtWeight * (prevEpochTargetAttestedEffectiveBalance / increment)
			reward += n / (activeIncrement * weightDenominator)
		}
	} else {
		penalty += baseReward * tgtWeight / weightDenominator
	}

	// Process head reward / penalty
	if correctlyVotedHead && !val.Slashed {
		if !inactivityLeak {
			n := baseReward * headWeight * (prevEpochHeadAttestedEffectiveBalance / increment)
			reward += n / (activeIncrement * weightDenominator)
		}
	}

	// Process finality delay penalty
	// Apply an additional penalty to validators that did not vote on the correct target or slashed
	if !correctlyVotedTarget || val.Slashed {
		n, err := mathprysm.Mul64(effectiveBalance, inactivityScore)
		if err != nil {
			return 0, 0, err
		}
		penalty += n / inactivityDenominator
	}

	return reward, penalty, nil
}

// def get_attestation_participation_flag_indices(state: BeaconState, data: AttestationData, inclusion_delay: uint64) -> Sequence[int]:
//
//	"""
//	Return the flag indices that are satisfied by an attestation.
//	"""
//	if data.target.epoch == get_current_epoch(state):
//	justified_checkpoint = state.current_justified_checkpoint
//	else:
//	justified_checkpoint = state.previous_justified_checkpoint
//
//	# Matching roots
//	is_matching_source = data.source == justified_checkpoint
//	is_matching_target = is_matching_source and data.target.root == get_block_root(state, data.target.epoch)
//	is_matching_head = is_matching_target and data.beacon_block_root == get_block_root_at_slot(state, data.slot)
//	assert is_matching_source
//
//	participation_flag_indices = []
//	if is_matching_source and inclusion_delay <= integer_squareroot(SLOTS_PER_EPOCH):
//	participation_flag_indices.append(TIMELY_SOURCE_FLAG_INDEX)
//	if is_matching_target and inclusion_delay <= SLOTS_PER_EPOCH:
//	participation_flag_indices.append(TIMELY_TARGET_FLAG_INDEX)
//	if is_matching_head and inclusion_delay == MIN_ATTESTATION_INCLUSION_DELAY:
//	participation_flag_indices.append(TIMELY_HEAD_FLAG_INDEX)
//
//	return participation_flag_indices
func getAttestationParticipationFlagIndices(beaconState *apimiddleware.BeaconStateJson, pendingAttestation *apimiddleware.PendingAttestationJson) ([]uint8, error) {
	if beaconState == nil {
		return nil, errors.New("beacon state is nil")
	}

	currentSlot, err := strconv.ParseUint(beaconState.Slot, 10, 64)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse slot `%s`", beaconState.Slot)
	}

	currentEpoch := slots.ToEpoch(primitives.Slot(currentSlot))

	if pendingAttestation == nil {
		return nil, errors.New("pending attestation is nil")
	}

	if pendingAttestation.Data == nil {
		return nil, errors.New("pending attestation data is nil")
	}

	if pendingAttestation.Data.Target == nil {
		return nil, errors.New("pending attestation data target is nil")
	}

	attestationDataTargetEpoch, err := strconv.ParseUint(pendingAttestation.Data.Target.Epoch, 10, 64)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse pending attestation data target epoch `%s`", pendingAttestation.Data.Target.Epoch)
	}

	var justifiedCheckpoint *apimiddleware.CheckpointJson
	if primitives.Epoch(attestationDataTargetEpoch) == currentEpoch {
		if beaconState.CurrentJustifiedCheckpoint == nil {
			return nil, errors.New("current justified checkpoint is nil")
		}

		justifiedCheckpoint = beaconState.CurrentJustifiedCheckpoint
	} else {
		if beaconState.PreviousJustifiedCheckpoint == nil {
			return nil, errors.New("previous justified checkpoint is nil")
		}

		justifiedCheckpoint = beaconState.PreviousJustifiedCheckpoint
	}

	if pendingAttestation.Data.Source == nil {
		return nil, errors.New("pending attestation data source is nil")
	}

	targetBlockRoot, err := getBlockRoot(beaconState, primitives.Epoch(attestationDataTargetEpoch))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get block root for epoch `%d`", attestationDataTargetEpoch)
	}

	attestationSlot, err := strconv.ParseUint(pendingAttestation.Data.Slot, 10, 64)
	if err != nil {
		return nil, errors.Wrapf(err, "failed or parse pending attestation slot `%s`", pendingAttestation.Data.Slot)
	}

	headBlockRoot, err := getBlockRootAtSlot(beaconState, primitives.Slot(attestationSlot))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get block root at slot `%d`", attestationSlot)
	}

	isMatchingSource := pendingAttestation.Data.Source.Epoch == justifiedCheckpoint.Epoch && pendingAttestation.Data.Source.Root == justifiedCheckpoint.Root
	isMatchingTarget := isMatchingSource && pendingAttestation.Data.Target.Root == targetBlockRoot
	isMatchingHead := isMatchingTarget && pendingAttestation.Data.BeaconBlockRoot == headBlockRoot

	if !isMatchingSource {
		return nil, errors.New("pending attestation source doesn't match the justified checkpoint")
	}

	cfg := params.BeaconConfig()
	participationFlagIndices := make([]uint8, 0, 3)

	inclusionDelay, err := strconv.ParseUint(pendingAttestation.InclusionDelay, 10, 64)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse inclusion delat `%s`", pendingAttestation.InclusionDelay)
	}

	if isMatchingSource && primitives.Slot(inclusionDelay) <= cfg.SqrRootSlotsPerEpoch {
		participationFlagIndices = append(participationFlagIndices, cfg.TimelySourceFlagIndex)
	}

	if isMatchingTarget && primitives.Slot(inclusionDelay) <= cfg.SlotsPerEpoch {
		participationFlagIndices = append(participationFlagIndices, cfg.TimelyTargetFlagIndex)
	}

	if isMatchingHead && primitives.Slot(inclusionDelay) == cfg.MinAttestationInclusionDelay {
		participationFlagIndices = append(participationFlagIndices, cfg.TimelyHeadFlagIndex)
	}

	return participationFlagIndices, nil
}

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
func (c beaconApiBeaconChainClient) translateParticipation(
	ctx context.Context,
	beaconState *apimiddleware.BeaconStateJson,
	pendingAttestations []*apimiddleware.PendingAttestationJson,
) ([]byte, error) {
	if beaconState == nil {
		return nil, errors.New("beacon state is nil")
	}

	epochParticipations := make([]byte, len(beaconState.Validators))
	for _, pendingAttestation := range pendingAttestations {
		if pendingAttestation == nil {
			return nil, errors.New("pending attestation is nil")
		}

		participationFlagIndices, err := getAttestationParticipationFlagIndices(beaconState, pendingAttestation)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get attestation participation flag indices")
		}

		aggregationBits, err := hexutil.Decode(pendingAttestation.AggregationBits)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to decode aggregation bits `%s`", aggregationBits)
		}

		attestingIndices, err := c.getAttestingIndices(ctx, beaconState, pendingAttestation.Data, bitfield.Bitlist(aggregationBits))
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get attesting indices")
		}

		for _, attestingIndex := range attestingIndices {
			for _, flagIndex := range participationFlagIndices {
				epochParticipations[attestingIndex], err = altair.AddValidatorFlag(epochParticipations[attestingIndex], flagIndex)
				if err != nil {
					return nil, errors.Wrapf(err, "failed to add validator flag with index `%d`", flagIndex)
				}
			}
		}
	}

	return epochParticipations, nil
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
	attestationData *apimiddleware.AttestationDataJson,
	bits bitfield.Bitlist,
) ([]primitives.ValidatorIndex, error) {
	if attestationData == nil {
		return nil, errors.New("attestation data is nil")
	}

	attestationSlot, err := strconv.ParseUint(attestationData.Slot, 10, 64)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse attestation slot `%s`", attestationData.Slot)
	}

	attestationCommitteeIndex, err := strconv.ParseUint(attestationData.CommitteeIndex, 10, 64)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse attestation committee index `%s`", attestationData.CommitteeIndex)
	}

	committee, err := c.getBeaconCommittee(ctx, primitives.Slot(attestationSlot), primitives.CommitteeIndex(attestationCommitteeIndex))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get committee for committee index `%d` and slot `%d`", attestationCommitteeIndex, attestationSlot)
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
