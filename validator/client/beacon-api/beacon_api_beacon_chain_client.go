package beacon_api

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/pkg/errors"
	"github.com/prysmaticlabs/go-bitfield"
	"github.com/prysmaticlabs/prysm/v4/beacon-chain/core/altair"
	"github.com/prysmaticlabs/prysm/v4/beacon-chain/rpc/apimiddleware"
	"github.com/prysmaticlabs/prysm/v4/config/params"
	"github.com/prysmaticlabs/prysm/v4/consensus-types/primitives"
	math2 "github.com/prysmaticlabs/prysm/v4/math"
	ethpb "github.com/prysmaticlabs/prysm/v4/proto/prysm/v1alpha1"
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
	// inactivityScores := make([]uint64, len(pubkeys))

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
		currentEpochSlot = primitives.Slot(slot)
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

	currentEffectiveBalances := make([]uint64, len(pubkeys))
	balancesBeforeEpochTransition := make([]uint64, len(pubkeys))
	balancesAfterEpochTransition := make([]uint64, len(pubkeys))

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

		effectiveBalance, err := strconv.ParseUint(stateValidator.Validator.EffectiveBalance, 10, 64)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse effective balance `%s` for validator index `%d`", stateValidator.Validator.EffectiveBalance, validatorIndex)
		}
		currentEffectiveBalances[idx] = effectiveBalance

		validatorPubkeyToIndex[stateValidator.Validator.PublicKey] = primitives.ValidatorIndex(validatorIndex)
	}

	previousEpochParticipations := make([]byte, len(pubkeys))

	switch beaconState := beaconState.(type) {
	case apimiddleware.BeaconStateJson:
		previousGlobalEpochParticipations, err := c.translateParticipation(ctx, &beaconState, beaconState.PreviousEpochAttestations)
		if err != nil {
			return nil, errors.Wrap(err, "failed to translate previous epoch attestations")
		}

		for idx, validatorPubKey := range pubkeys {
			validatorIndex, ok := validatorPubkeyToIndex[validatorPubKey]
			if !ok {
				return nil, errors.Errorf("failed to get index for validator `%s`", validatorPubKey)
			}

			previousEpochParticipations[idx] = previousGlobalEpochParticipations[validatorIndex]
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
			previousEpochParticipations[idx] = previousEpochParticipationByte

		}
	case apimiddleware.BeaconStateBellatrixJson:
	case apimiddleware.BeaconStateCapellaJson:
	}

	cfg := params.BeaconConfig()
	correctlyVotedSource := make([]bool, len(previousEpochParticipations))
	correctlyVotedTarget := make([]bool, len(previousEpochParticipations))
	correctlyVotedHead := make([]bool, len(previousEpochParticipations))

	for idx, previousEpochParticipation := range previousEpochParticipations {
		hasSourceFlag, err := altair.HasValidatorFlag(previousEpochParticipation, cfg.TimelySourceFlagIndex)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get source flag from previous epoch participation")
		}
		correctlyVotedSource[idx] = hasSourceFlag

		hasTargetFlag, err := altair.HasValidatorFlag(previousEpochParticipation, cfg.TimelyTargetFlagIndex)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get target flag from previous epoch participation")
		}
		correctlyVotedTarget[idx] = hasTargetFlag

		hasHeadFlag, err := altair.HasValidatorFlag(previousEpochParticipation, cfg.TimelyHeadFlagIndex)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get head flag from previous epoch participation")
		}
		correctlyVotedHead[idx] = hasHeadFlag
	}

	validatorPerformanceResponse := &ethpb.ValidatorPerformanceResponse{
		CurrentEffectiveBalances:      currentEffectiveBalances,
		CorrectlyVotedSource:          correctlyVotedSource,
		CorrectlyVotedTarget:          correctlyVotedTarget,
		CorrectlyVotedHead:            correctlyVotedHead,
		BalancesBeforeEpochTransition: balancesBeforeEpochTransition,
		BalancesAfterEpochTransition:  balancesAfterEpochTransition, // TODO (pavignol): Correctly query the balances before epoch transition
		MissingValidators:             [][]byte{},                   // TODO (pavignol): Figure out which validators are missing
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
