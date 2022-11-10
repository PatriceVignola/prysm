//go:build use_beacon_api
// +build use_beacon_api

package beacon_api

import (
	"bytes"
	"context"
	"sort"
	"strings"

	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/pkg/errors"
	types "github.com/prysmaticlabs/prysm/v3/consensus-types/primitives"
	ethpb "github.com/prysmaticlabs/prysm/v3/proto/prysm/v1alpha1"
	iface "github.com/prysmaticlabs/prysm/v3/validator/client/iface"
)

type beaconApiValidatorClient struct {
	url        string
	httpClient http.Client
}

func NewBeaconApiValidatorClient(url string, timeout time.Duration) iface.ValidatorClient {
	return &beaconApiValidatorClient{url, http.Client{Timeout: timeout}}
}

func (c *beaconApiValidatorClient) GetDuties(_ context.Context, in *ethpb.DutiesRequest) (*ethpb.DutiesResponse, error) {
	currentEpochDuties, err := c.getDuties(uint64(in.Epoch), in.PublicKeys)
	if err != nil {
		return nil, err
	}

	nextEpochDuties, err := c.getDuties(uint64(in.Epoch)+1, in.PublicKeys)
	if err != nil {
		return nil, err
	}

	dutiesResponse := &ethpb.DutiesResponse{}
	dutiesResponse.Duties = currentEpochDuties
	dutiesResponse.CurrentEpochDuties = currentEpochDuties
	dutiesResponse.NextEpochDuties = nextEpochDuties
	return dutiesResponse, nil
}

func (*beaconApiValidatorClient) CheckDoppelGanger(_ context.Context, _ *ethpb.DoppelGangerRequest) (*ethpb.DoppelGangerResponse, error) {
	// TODO: Implement me
	panic("beaconApiValidatorClient.CheckDoppelGanger is not implemented")
}

func (*beaconApiValidatorClient) DomainData(_ context.Context, _ *ethpb.DomainRequest) (*ethpb.DomainResponse, error) {
	// TODO: Implement me
	panic("beaconApiValidatorClient.DomainData is not implemented")
}

func (*beaconApiValidatorClient) GetAttestationData(_ context.Context, _ *ethpb.AttestationDataRequest) (*ethpb.AttestationData, error) {
	// TODO: Implement me
	panic("beaconApiValidatorClient.GetAttestationData is not implemented")
}

func (*beaconApiValidatorClient) GetBeaconBlock(_ context.Context, _ *ethpb.BlockRequest) (*ethpb.GenericBeaconBlock, error) {
	// TODO: Implement me
	panic("beaconApiValidatorClient.GetBeaconBlock is not implemented")
}

func (*beaconApiValidatorClient) GetFeeRecipientByPubKey(_ context.Context, _ *ethpb.FeeRecipientByPubKeyRequest) (*ethpb.FeeRecipientByPubKeyResponse, error) {
	// TODO: Implement me
	panic("beaconApiValidatorClient.GetFeeRecipientByPubKey is not implemented")
}

func (*beaconApiValidatorClient) GetSyncCommitteeContribution(_ context.Context, _ *ethpb.SyncCommitteeContributionRequest) (*ethpb.SyncCommitteeContribution, error) {
	// TODO: Implement me
	panic("beaconApiValidatorClient.GetSyncCommitteeContribution is not implemented")
}

func (*beaconApiValidatorClient) GetSyncMessageBlockRoot(_ context.Context, _ *empty.Empty) (*ethpb.SyncMessageBlockRootResponse, error) {
	// TODO: Implement me
	panic("beaconApiValidatorClient.GetSyncMessageBlockRoot is not implemented")
}

func (*beaconApiValidatorClient) GetSyncSubcommitteeIndex(_ context.Context, _ *ethpb.SyncSubcommitteeIndexRequest) (*ethpb.SyncSubcommitteeIndexResponse, error) {
	// TODO: Implement me
	panic("beaconApiValidatorClient.GetSyncSubcommitteeIndex is not implemented")
}

func (c *beaconApiValidatorClient) MultipleValidatorStatus(_ context.Context, in *ethpb.MultipleValidatorStatusRequest) (*ethpb.MultipleValidatorStatusResponse, error) {
	return c.getMultipleValidatorStatus(in.PublicKeys, in.Indices)
}

func (*beaconApiValidatorClient) PrepareBeaconProposer(_ context.Context, _ *ethpb.PrepareBeaconProposerRequest) (*empty.Empty, error) {
	// TODO: Implement me
	panic("beaconApiValidatorClient.PrepareBeaconProposer is not implemented")
}

func (*beaconApiValidatorClient) ProposeAttestation(_ context.Context, _ *ethpb.Attestation) (*ethpb.AttestResponse, error) {
	// TODO: Implement me
	panic("beaconApiValidatorClient.ProposeAttestation is not implemented")
}

func (*beaconApiValidatorClient) ProposeBeaconBlock(_ context.Context, _ *ethpb.GenericSignedBeaconBlock) (*ethpb.ProposeResponse, error) {
	// TODO: Implement me
	panic("beaconApiValidatorClient.ProposeBeaconBlock is not implemented")
}

func (*beaconApiValidatorClient) ProposeExit(_ context.Context, _ *ethpb.SignedVoluntaryExit) (*ethpb.ProposeExitResponse, error) {
	// TODO: Implement me
	panic("beaconApiValidatorClient.ProposeExit is not implemented")
}

func (*beaconApiValidatorClient) StreamBlocksAltair(_ context.Context, _ *ethpb.StreamBlocksRequest) (ethpb.BeaconNodeValidator_StreamBlocksAltairClient, error) {
	// TODO: Implement me
	panic("beaconApiValidatorClient.StreamBlocksAltair is not implemented")
}

func (*beaconApiValidatorClient) StreamDuties(_ context.Context, _ *ethpb.DutiesRequest) (ethpb.BeaconNodeValidator_StreamDutiesClient, error) {
	// TODO: Implement me
	panic("beaconApiValidatorClient.StreamDuties is not implemented")
}

func (*beaconApiValidatorClient) SubmitAggregateSelectionProof(_ context.Context, _ *ethpb.AggregateSelectionRequest) (*ethpb.AggregateSelectionResponse, error) {
	// TODO: Implement me
	panic("beaconApiValidatorClient.SubmitAggregateSelectionProof is not implemented")
}

func (*beaconApiValidatorClient) SubmitSignedAggregateSelectionProof(_ context.Context, _ *ethpb.SignedAggregateSubmitRequest) (*ethpb.SignedAggregateSubmitResponse, error) {
	// TODO: Implement me
	panic("beaconApiValidatorClient.SubmitSignedAggregateSelectionProof is not implemented")
}

func (*beaconApiValidatorClient) SubmitSignedContributionAndProof(_ context.Context, _ *ethpb.SignedContributionAndProof) (*empty.Empty, error) {
	// TODO: Implement me
	panic("beaconApiValidatorClient.SubmitSignedContributionAndProof is not implemented")
}

func (*beaconApiValidatorClient) SubmitSyncMessage(_ context.Context, _ *ethpb.SyncCommitteeMessage) (*empty.Empty, error) {
	// TODO: Implement me
	panic("beaconApiValidatorClient.SubmitSyncMessage is not implemented")
}

func (*beaconApiValidatorClient) SubmitValidatorRegistrations(_ context.Context, _ *ethpb.SignedValidatorRegistrationsV1) (*empty.Empty, error) {
	// TODO: Implement me
	panic("beaconApiValidatorClient.SubmitValidatorRegistrations is not implemented")
}

func (*beaconApiValidatorClient) SubscribeCommitteeSubnets(_ context.Context, _ *ethpb.CommitteeSubnetsSubscribeRequest) (*empty.Empty, error) {
	// TODO: Implement me
	panic("beaconApiValidatorClient.SubscribeCommitteeSubnets is not implemented")
}

func (*beaconApiValidatorClient) ValidatorIndex(_ context.Context, _ *ethpb.ValidatorIndexRequest) (*ethpb.ValidatorIndexResponse, error) {
	// TODO: Implement me
	panic("beaconApiValidatorClient.ValidatorIndex is not implemented")
}

func (c *beaconApiValidatorClient) ValidatorStatus(_ context.Context, in *ethpb.ValidatorStatusRequest) (*ethpb.ValidatorStatusResponse, error) {
	return c.getValidatorStatus(in.PublicKey)
}

func (*beaconApiValidatorClient) WaitForActivation(_ context.Context, _ *ethpb.ValidatorActivationRequest) (ethpb.BeaconNodeValidator_WaitForActivationClient, error) {
	// TODO: Implement me
	panic("beaconApiValidatorClient.WaitForActivation is not implemented")
}

// Deprecated: Do not use.
func (c *beaconApiValidatorClient) WaitForChainStart(_ context.Context, _ *empty.Empty) (*ethpb.ChainStartResponse, error) {
	resp, err := c.httpClient.Get(c.url + "/eth/v1/beacon/genesis")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err = resp.Body.Close(); err != nil {
			return
		}
	}()

	if resp.StatusCode != http.StatusOK {
		errorJson := ErrorResponseJson{}
		err = json.NewDecoder(resp.Body).Decode(&errorJson)
		if err != nil {
			return nil, err
		}

		return nil, errors.Errorf("error %d: %s", errorJson.Code, errorJson.Message)
	}

	genesisJson := GenesisResponseJson{}
	err = json.NewDecoder(resp.Body).Decode(&genesisJson)
	if err != nil {
		return nil, err
	}

	genesisTime, err := strconv.ParseUint(genesisJson.Data.GenesisTime, 10, 64)
	if err != nil {
		return nil, err
	}

	chainStartResponse := &ethpb.ChainStartResponse{}
	chainStartResponse.Started = true
	chainStartResponse.GenesisTime = genesisTime

	genesisValidatorRoot, err := hex.DecodeString(genesisJson.Data.GenesisValidatorsRoot)
	if err != nil {
		return nil, err
	}
	chainStartResponse.GenesisValidatorsRoot = genesisValidatorRoot

	return chainStartResponse, nil
}

func (c *beaconApiValidatorClient) getValidatorStatus(pubkey []byte) (*ethpb.ValidatorStatusResponse, error) {
	resp, err := c.httpClient.Get(c.url + "/eth/v1/beacon/states/head/validators/0x" + hex.EncodeToString(pubkey))
	if err != nil {
		return nil, err
	}
	defer func() {
		if err = resp.Body.Close(); err != nil {
			return
		}
	}()

	if resp.StatusCode != http.StatusOK {
		errorJson := ErrorResponseJson{}
		err = json.NewDecoder(resp.Body).Decode(&errorJson)
		if err != nil {
			return nil, err
		}

		return nil, errors.Errorf("error %d: %s", errorJson.Code, errorJson.Message)
	}

	responseJson := &StateValidatorResponseJson{}
	err = json.NewDecoder(resp.Body).Decode(&responseJson)
	if err != nil {
		return nil, err
	}

	activationQueue, err := c.getActivationQueue()
	if err != nil {
		return nil, err
	}

	statusResponse, err := parseValidatorStatusResponse(responseJson.Data, activationQueue)
	if err != nil {
		return nil, err
	}

	return statusResponse, nil
}

func (c *beaconApiValidatorClient) getMultipleValidatorStatus(pubkeys [][]byte, indices []int64) (*ethpb.MultipleValidatorStatusResponse, error) {
	query := c.url + "/eth/v1/beacon/states/head/validators"

	if len(indices) > 0 || len(pubkeys) > 0 {
		var queryArgs strings.Builder
		if _, err := queryArgs.WriteString("?id="); err != nil {
			return nil, err
		}

		// Append the indices to the query string
		for i, validatorIndex := range indices {
			if _, err := queryArgs.WriteString(strconv.FormatInt(validatorIndex, 10)); err != nil {
				return nil, err
			}

			// Don't add a comma if it's the last element
			if i < len(indices)-1 || len(pubkeys) != 0 {
				if _, err := queryArgs.WriteString(","); err != nil {
					return nil, err
				}
			}
		}

		// Append the public keys to the query string
		for i, pubkey := range pubkeys {
			if _, err := queryArgs.WriteString("0x" + hex.EncodeToString(pubkey)); err != nil {
				return nil, err
			}

			// Don't add a comma if it's the last element
			if i < len(pubkeys)-1 {
				if _, err := queryArgs.WriteString(","); err != nil {
					return nil, err
				}
			}
		}

		query += queryArgs.String()
	}

	resp, err := c.httpClient.Get(query)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err = resp.Body.Close(); err != nil {
			return
		}
	}()

	if resp.StatusCode != http.StatusOK {
		errorJson := ErrorResponseJson{}
		err = json.NewDecoder(resp.Body).Decode(&errorJson)
		if err != nil {
			return nil, err
		}

		return nil, errors.Errorf("error %d: %s", errorJson.Code, errorJson.Message)
	}

	responseJson := &StateValidatorsResponseJson{}
	err = json.NewDecoder(resp.Body).Decode(&responseJson)
	if err != nil {
		return nil, err
	}

	activationQueue, err := c.getActivationQueue()
	if err != nil {
		return nil, err
	}

	response := &ethpb.MultipleValidatorStatusResponse{}
	for _, responseData := range responseJson.Data {
		validatorIndex, err := strconv.ParseUint(responseData.Index, 10, 64)
		if err != nil {
			return nil, err
		}

		response.Indices = append(response.Indices, types.ValidatorIndex(validatorIndex))
		response.PublicKeys = append(response.PublicKeys, []byte(responseData.Validator.PublicKey))

		statusResponse, err := parseValidatorStatusResponse(responseData, activationQueue)
		if err != nil {
			return nil, err
		}

		response.Statuses = append(response.Statuses, statusResponse)
	}

	return response, nil
}

// Returns the index of the next validator to be activated, or nil if the activation queue is empty
func (c *beaconApiValidatorClient) getActivationQueue() (*StateValidatorsResponseJson, error) {
	resp, err := c.httpClient.Get(c.url + "/eth/v1/beacon/states/head/validators?status=pending_queued")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err = resp.Body.Close(); err != nil {
			return
		}
	}()

	if resp.StatusCode != http.StatusOK {
		errorJson := ErrorResponseJson{}
		err = json.NewDecoder(resp.Body).Decode(&errorJson)
		if err != nil {
			return nil, err
		}

		return nil, errors.Errorf("error %d: %s", errorJson.Code, errorJson.Message)
	}

	responseJson := &StateValidatorsResponseJson{}
	err = json.NewDecoder(resp.Body).Decode(&responseJson)
	if err != nil {
		return nil, err
	}

	if len(responseJson.Data) == 0 {
		return nil, nil
	}

	sort.Slice(responseJson.Data, func(i, j int) bool {
		myActivationEligibilityEpoch, err := strconv.ParseUint(responseJson.Data[i].Validator.ActivationEligibilityEpoch, 10, 64)
		if err != nil {
			return false
		}

		otherActivationEligibilityEpoch, err := strconv.ParseUint(responseJson.Data[j].Validator.ActivationEligibilityEpoch, 10, 64)
		if err != nil {
			return false
		}

		if myActivationEligibilityEpoch == otherActivationEligibilityEpoch {
			myIndex, err := strconv.ParseUint(responseJson.Data[i].Index, 10, 64)
			if err != nil {
				return false
			}

			otherIndex, err := strconv.ParseUint(responseJson.Data[j].Index, 10, 64)
			if err != nil {
				return false
			}

			return myIndex < otherIndex
		}

		return myActivationEligibilityEpoch < otherActivationEligibilityEpoch
	})

	return responseJson, nil
}

func (c *beaconApiValidatorClient) getAttesterDuties(epoch uint64, validatorIndices []string) (*AttesterDutiesResponseJson, error) {
	jsonIndices, err := json.Marshal(validatorIndices)
	if err != nil {
		return nil, err
	}

	query := c.url + "/eth/v1/validator/duties/attester/" + strconv.FormatUint(epoch, 10)
	resp, err := c.httpClient.Post(query, "application/json", bytes.NewBuffer(jsonIndices))
	if err != nil {
		return nil, err
	}
	defer func() {
		if err = resp.Body.Close(); err != nil {
			return
		}
	}()

	if resp.StatusCode != http.StatusOK {
		errorJson := ErrorResponseJson{}
		err = json.NewDecoder(resp.Body).Decode(&errorJson)
		if err != nil {
			return nil, err
		}

		return nil, errors.Errorf("error %d: %s", errorJson.Code, errorJson.Message)
	}

	dutiesJson := &AttesterDutiesResponseJson{}
	err = json.NewDecoder(resp.Body).Decode(&dutiesJson)
	if err != nil {
		return nil, err
	}

	return dutiesJson, nil
}

func (c *beaconApiValidatorClient) getProposerDuties(epoch uint64) (*ProposerDutiesResponseJson, error) {
	resp, err := c.httpClient.Get(c.url + "/eth/v1/validator/duties/proposer/" + strconv.FormatUint(epoch, 10))
	if err != nil {
		return nil, err
	}
	defer func() {
		if err = resp.Body.Close(); err != nil {
			return
		}
	}()

	if resp.StatusCode != http.StatusOK {
		errorJson := ErrorResponseJson{}
		err = json.NewDecoder(resp.Body).Decode(&errorJson)
		if err != nil {
			return nil, err
		}

		return nil, errors.Errorf("error %d: %s", errorJson.Code, errorJson.Message)
	}

	dutiesJson := &ProposerDutiesResponseJson{}
	err = json.NewDecoder(resp.Body).Decode(&dutiesJson)
	if err != nil {
		return nil, err
	}

	return dutiesJson, nil
}

func (c *beaconApiValidatorClient) getSyncDuties(epoch uint64, validatorIndices []string) (*SyncCommitteeDutiesResponseJson, error) {
	jsonIndices, err := json.Marshal(validatorIndices)
	if err != nil {
		return nil, err
	}

	query := c.url + "/eth/v1/validator/duties/sync/" + strconv.FormatUint(epoch, 10)
	resp, err := c.httpClient.Post(query, "application/json", bytes.NewBuffer(jsonIndices))
	if err != nil {
		return nil, err
	}
	defer func() {
		if err = resp.Body.Close(); err != nil {
			return
		}
	}()

	if resp.StatusCode != http.StatusOK {
		errorJson := ErrorResponseJson{}
		err = json.NewDecoder(resp.Body).Decode(&errorJson)
		if err != nil {
			return nil, err
		}

		return nil, errors.Errorf("error %d: %s", errorJson.Code, errorJson.Message)
	}

	dutiesJson := &SyncCommitteeDutiesResponseJson{}
	err = json.NewDecoder(resp.Body).Decode(&dutiesJson)
	if err != nil {
		return nil, err
	}

	return dutiesJson, nil
}

func (c *beaconApiValidatorClient) getDuties(epoch uint64, pubkeys [][]byte) ([]*ethpb.DutiesResponse_Duty, error) {
	multipleValidatorStatus, err := c.getMultipleValidatorStatus(pubkeys, []int64{})
	if err != nil {
		return nil, err
	}

	validatorIndices := multipleValidatorStatus.Indices
	indicesMapping := make(map[uint64]*ethpb.DutiesResponse_Duty)
	validatorStringIndices := make([]string, 0, len(validatorIndices))
	for _, validatorIndex := range validatorIndices {
		validatorStringIndices = append(validatorStringIndices, strconv.FormatUint(uint64(validatorIndex), 10))
		indicesMapping[uint64(validatorIndex)] = &ethpb.DutiesResponse_Duty{}
	}

	attesterDutiesJson, err := c.getAttesterDuties(epoch, validatorStringIndices)
	if err != nil {
		return nil, err
	}

	proposerDutiesJson, err := c.getProposerDuties(epoch)
	if err != nil {
		return nil, err
	}

	syncDutiesJson, err := c.getSyncDuties(epoch, validatorStringIndices)
	if err != nil {
		return nil, err
	}

	// Get the attester duties
	for _, attesterDutyData := range attesterDutiesJson.Data {
		validatorIndex, err := strconv.ParseUint(attesterDutyData.ValidatorIndex, 10, 64)
		if err != nil {
			return nil, err
		}

		attesterSlot, err := strconv.ParseUint(attesterDutyData.Slot, 10, 64)
		if err != nil {
			return nil, err
		}

		if dutyResponse, exists := indicesMapping[validatorIndex]; exists {
			dutyResponse.PublicKey = []byte(attesterDutyData.Pubkey)
			dutyResponse.ValidatorIndex = types.ValidatorIndex(validatorIndex)
			dutyResponse.AttesterSlot = types.Slot(attesterSlot)
		}
	}

	// Get the proposer duties
	for _, proposerDutyData := range proposerDutiesJson.Data {
		validatorIndex, err := strconv.ParseUint(proposerDutyData.ValidatorIndex, 10, 64)
		if err != nil {
			return nil, err
		}

		proposerSlot, err := strconv.ParseUint(proposerDutyData.ValidatorIndex, 10, 64)
		if err != nil {
			return nil, err
		}

		if dutyResponse, exists := indicesMapping[validatorIndex]; exists {
			dutyResponse.ProposerSlots = append(dutyResponse.ProposerSlots, types.Slot(proposerSlot))
		}
	}

	// Get the sync duties
	for _, dutyData := range syncDutiesJson.Data {
		validatorIndex, err := strconv.ParseUint(dutyData.ValidatorIndex, 10, 64)
		if err != nil {
			return nil, err
		}

		if dutyResponse, exists := indicesMapping[validatorIndex]; exists {
			dutyResponse.PublicKey = []byte(dutyData.Pubkey)
			dutyResponse.IsSyncCommittee = true

			for _, committeeIndex := range dutyData.ValidatorSyncCommitteeIndices {
				uintCommitteeIndex, err := strconv.ParseUint(committeeIndex, 10, 64)
				if err != nil {
					return nil, err
				}

				dutyResponse.Committee = append(dutyResponse.Committee, types.ValidatorIndex(uintCommitteeIndex))
			}
		}
	}

	// Finally, fill the return array with the elements from the map
	duties := make([]*ethpb.DutiesResponse_Duty, 0, len(validatorIndices))
	for pubkeyIndex, validatorIndex := range validatorIndices {
		validatorStatus, err := c.getValidatorStatus(pubkeys[pubkeyIndex])
		if err != nil {
			return nil, err
		}

		dutyResponse := indicesMapping[uint64(validatorIndex)]
		dutyResponse.ValidatorIndex = types.ValidatorIndex(validatorIndex)
		dutyResponse.PublicKey = pubkeys[pubkeyIndex]
		dutyResponse.Status = validatorStatus.Status
		duties = append(duties, dutyResponse)
	}

	return duties, nil
}

func parseValidatorStatusResponse(responseData *ValidatorContainerJson, activationQueue *StateValidatorsResponseJson) (*ethpb.ValidatorStatusResponse, error) {
	activationEpoch, err := strconv.ParseUint(responseData.Validator.ActivationEpoch, 10, 64)
	if err != nil {
		return nil, err
	}

	statusResponse := &ethpb.ValidatorStatusResponse{}
	statusResponse.ActivationEpoch = types.Epoch(activationEpoch)
	statusResponse.Status = convertStringStatusToEnum(responseData.Status)

	isPending := statusResponse.Status == ethpb.ValidatorStatus_DEPOSITED ||
		statusResponse.Status == ethpb.ValidatorStatus_PARTIALLY_DEPOSITED ||
		statusResponse.Status == ethpb.ValidatorStatus_PENDING

	if isPending {
		// Count the number of validators that are ahead of us in the activation queue
		var indexInActivationQueue uint64
		for i, pendingValidatorData := range activationQueue.Data {
			if pendingValidatorData.Index == responseData.Index {
				indexInActivationQueue = uint64(i)
				break
			}
		}

		statusResponse.PositionInActivationQueue = indexInActivationQueue + 1
	}

	return statusResponse, nil
}

func convertStringStatusToEnum(jsonStatus string) ethpb.ValidatorStatus {
	switch jsonStatus {
	case "pending_initialized":
		return ethpb.ValidatorStatus_PARTIALLY_DEPOSITED
	case "pending_queued":
		return ethpb.ValidatorStatus_DEPOSITED
	case "active_ongoing":
		return ethpb.ValidatorStatus_ACTIVE
	case "active_exiting":
		return ethpb.ValidatorStatus_EXITING
	case "active_slashed":
		return ethpb.ValidatorStatus_SLASHING
	case "exited_unslashed":
		return ethpb.ValidatorStatus_EXITED
	case "exited_slashed":
		return ethpb.ValidatorStatus_EXITED
	case "withdrawal_possible":
		return ethpb.ValidatorStatus_EXITED
	case "withdrawal_done":
		return ethpb.ValidatorStatus_EXITED
	default:
		return ethpb.ValidatorStatus_UNKNOWN_STATUS
	}
}
