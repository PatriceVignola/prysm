//go:build use_beacon_api
// +build use_beacon_api

package beacon_api

import (
	"bytes"
	"context"
	"fmt"
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

func (c *beaconApiValidatorClient) DomainData(_ context.Context, in *ethpb.DomainRequest) (*ethpb.DomainResponse, error) {
	// 1. Get genesis_fork_version and genesis_validators_root from the Genesis call
	genesis, err := c.getGenesis()
	if err != nil {
		return nil, err
	}

	// Remove the leading 0x from the string before decoding it to bytes
	forkVersion, err := hex.DecodeString(genesis.Data.GenesisForkVersion[2:])
	if err != nil {
		return nil, err
	}

	genesisValidatorRoot, err := hex.DecodeString(genesis.Data.GenesisValidatorsRoot[2:])
	if err != nil {
		return nil, err
	}

	// 2. Compute hash_tree_root of genesis_fork_version and genesis_validators_root
	forkDataRoot, err := (&ethpb.ForkData{
		CurrentVersion:        forkVersion,
		GenesisValidatorsRoot: genesisValidatorRoot,
	}).HashTreeRoot()
	if err != nil {
		return nil, err
	}

	// 3. Append the first 4 bytes of the domain type to the last 28 bytes of the fork data root
	var signatureDomain []byte
	signatureDomain = append(signatureDomain, in.Domain[:4]...)
	signatureDomain = append(signatureDomain, forkDataRoot[:28]...)

	response := &ethpb.DomainResponse{SignatureDomain: signatureDomain}
	return response, nil
}

func (c *beaconApiValidatorClient) GetAttestationData(_ context.Context, in *ethpb.AttestationDataRequest) (*ethpb.AttestationData, error) {
	resp, err := c.httpClient.Get(c.url + fmt.Sprintf("/eth/v1/beacon/blocks/%d/attestations", in.Slot))
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

	blockAttestationsResponseJson := BlockAttestationsResponseJson{}
	err = json.NewDecoder(resp.Body).Decode(&blockAttestationsResponseJson)
	if err != nil {
		return nil, err
	}

	response := &ethpb.AttestationData{}

	for _, attestationJson := range blockAttestationsResponseJson.Data {
		committeeIndex, err := strconv.ParseUint(attestationJson.Data.CommitteeIndex, 10, 64)
		if err != nil {
			return nil, err
		}

		if committeeIndex != uint64(in.CommitteeIndex) {
			continue
		}

		// Remove the leading 0x from the string before decoding it to bytes
		beaconBlockRoot, err := hex.DecodeString(attestationJson.Data.BeaconBlockRoot[2:])
		if err != nil {
			return nil, err
		}

		slot, err := strconv.ParseUint(attestationJson.Data.Slot, 10, 64)
		if err != nil {
			return nil, err
		}

		sourceEpoch, err := strconv.ParseUint(attestationJson.Data.Source.Epoch, 10, 64)
		if err != nil {
			return nil, err
		}

		// Remove the leading 0x from the string before decoding it to bytes
		sourceRoot, err := hex.DecodeString(attestationJson.Data.Source.Root[2:])
		if err != nil {
			return nil, err
		}

		targetEpoch, err := strconv.ParseUint(attestationJson.Data.Target.Epoch, 10, 64)
		if err != nil {
			return nil, err
		}

		// Remove the leading 0x from the string before decoding it to bytes
		targetRoot, err := hex.DecodeString(attestationJson.Data.Target.Root[2:])
		if err != nil {
			return nil, err
		}

		response.BeaconBlockRoot = beaconBlockRoot
		response.CommitteeIndex = types.CommitteeIndex(committeeIndex)
		response.Slot = types.Slot(slot)
		response.Source.Epoch = types.Epoch(sourceEpoch)
		response.Source.Root = sourceRoot
		response.Target.Epoch = types.Epoch(targetEpoch)
		response.Target.Root = targetRoot
	}

	return response, nil
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

func (c *beaconApiValidatorClient) ProposeBeaconBlock(_ context.Context, in *ethpb.GenericSignedBeaconBlock) (*ethpb.ProposeResponse, error) {
	var consensusVersion string
	var signature []byte
	var beaconBlockRoot []byte

	var err error
	var marshalledSignedBeaconBlockJson []byte
	blinded := false

	switch blockType := in.Block.(type) {
	case *ethpb.GenericSignedBeaconBlock_Phase0:
		consensusVersion = "phase0"
		if len(blockType.Phase0.Block.Body.Attestations) > 0 {
			beaconBlockRoot = blockType.Phase0.Block.Body.Attestations[0].Data.BeaconBlockRoot
		}

		signedBeaconBlockJson := &SignedBeaconBlockContainerJson{}
		signedBeaconBlockJson.Message.Body = jsonifyBeaconBlockBody(blockType.Phase0.Block.Body)
		signedBeaconBlockJson.Message.ParentRoot = "0x" + hex.EncodeToString(blockType.Phase0.Block.ParentRoot)
		signedBeaconBlockJson.Message.ProposerIndex = strconv.FormatUint(uint64(blockType.Phase0.Block.ProposerIndex), 10)
		signedBeaconBlockJson.Message.Slot = strconv.FormatUint(uint64(blockType.Phase0.Block.Slot), 10)
		signedBeaconBlockJson.Message.StateRoot = "0x" + hex.EncodeToString(blockType.Phase0.Block.StateRoot)
		signedBeaconBlockJson.Signature = "0x" + hex.EncodeToString(signature)
		marshalledSignedBeaconBlockJson, err = json.Marshal(signedBeaconBlockJson)
		if err != nil {
			return nil, err
		}
	case *ethpb.GenericSignedBeaconBlock_Altair:
		consensusVersion = "altair"
		if len(blockType.Altair.Block.Body.Attestations) > 0 {
			beaconBlockRoot = blockType.Altair.Block.Body.Attestations[0].Data.BeaconBlockRoot
		}

		// Convert the phase0 fields of Altair to a BeaconBlockBody to be able to reuse jsonifyBeaconBlockBody
		beaconBlockBody := &ethpb.BeaconBlockBody{}
		signature = blockType.Altair.Signature
		beaconBlockBody.RandaoReveal = blockType.Altair.Block.Body.RandaoReveal
		beaconBlockBody.Eth1Data = blockType.Altair.Block.Body.Eth1Data
		beaconBlockBody.Graffiti = blockType.Altair.Block.Body.Graffiti
		beaconBlockBody.ProposerSlashings = blockType.Altair.Block.Body.ProposerSlashings
		beaconBlockBody.AttesterSlashings = blockType.Altair.Block.Body.AttesterSlashings
		beaconBlockBody.Attestations = blockType.Altair.Block.Body.Attestations
		beaconBlockBody.Deposits = blockType.Altair.Block.Body.Deposits
		beaconBlockBody.VoluntaryExits = blockType.Altair.Block.Body.VoluntaryExits
		signedBeaconBlockAltairJson := &SignedBeaconBlockAltairContainerJson{}
		signedBeaconBlockAltairJson.Signature = "0x" + hex.EncodeToString(signature)
		signedBeaconBlockAltairJson.Message.ParentRoot = "0x" + hex.EncodeToString(blockType.Altair.Block.ParentRoot)
		signedBeaconBlockAltairJson.Message.ProposerIndex = strconv.FormatUint(uint64(blockType.Altair.Block.ProposerIndex), 10)
		signedBeaconBlockAltairJson.Message.Slot = strconv.FormatUint(uint64(blockType.Altair.Block.Slot), 10)
		signedBeaconBlockAltairJson.Message.StateRoot = "0x" + hex.EncodeToString(blockType.Altair.Block.StateRoot)
		signedBeaconBlockAltairJson.Message.Body.BeaconBlockBodyJson = *jsonifyBeaconBlockBody(beaconBlockBody)
		signedBeaconBlockAltairJson.Message.Body.SyncAggregate.SyncCommitteeBits = "0x" + hex.EncodeToString(blockType.Altair.Block.Body.SyncAggregate.SyncCommitteeBits)
		signedBeaconBlockAltairJson.Message.Body.SyncAggregate.SyncCommitteeSignature = "0x" + hex.EncodeToString(blockType.Altair.Block.Body.SyncAggregate.SyncCommitteeSignature)
		marshalledSignedBeaconBlockJson, err = json.Marshal(signedBeaconBlockAltairJson)
		if err != nil {
			return nil, err
		}
	case *ethpb.GenericSignedBeaconBlock_Bellatrix:
		consensusVersion = "bellatrix"
		if len(blockType.Bellatrix.Block.Body.Attestations) > 0 {
			beaconBlockRoot = blockType.Bellatrix.Block.Body.Attestations[0].Data.BeaconBlockRoot
		}

		// Convert the phase0 fields of Bellatrix to a BeaconBlockBody to be able to reuse jsonifyBeaconBlockBody
		beaconBlockBody := &ethpb.BeaconBlockBody{}
		signature = blockType.Bellatrix.Signature
		beaconBlockBody.RandaoReveal = blockType.Bellatrix.Block.Body.RandaoReveal
		beaconBlockBody.Eth1Data = blockType.Bellatrix.Block.Body.Eth1Data
		beaconBlockBody.Graffiti = blockType.Bellatrix.Block.Body.Graffiti
		beaconBlockBody.ProposerSlashings = blockType.Bellatrix.Block.Body.ProposerSlashings
		beaconBlockBody.AttesterSlashings = blockType.Bellatrix.Block.Body.AttesterSlashings
		beaconBlockBody.Attestations = blockType.Bellatrix.Block.Body.Attestations
		beaconBlockBody.Deposits = blockType.Bellatrix.Block.Body.Deposits
		beaconBlockBody.VoluntaryExits = blockType.Bellatrix.Block.Body.VoluntaryExits
		signedBeaconBlockBellatrixJson := &SignedBeaconBlockBellatrixContainerJson{}
		signedBeaconBlockBellatrixJson.Signature = "0x" + hex.EncodeToString(signature)
		signedBeaconBlockBellatrixJson.Message.ParentRoot = "0x" + hex.EncodeToString(blockType.Bellatrix.Block.ParentRoot)
		signedBeaconBlockBellatrixJson.Message.ProposerIndex = strconv.FormatUint(uint64(blockType.Bellatrix.Block.ProposerIndex), 10)
		signedBeaconBlockBellatrixJson.Message.Slot = strconv.FormatUint(uint64(blockType.Bellatrix.Block.Slot), 10)
		signedBeaconBlockBellatrixJson.Message.StateRoot = "0x" + hex.EncodeToString(blockType.Bellatrix.Block.StateRoot)
		signedBeaconBlockBellatrixJson.Message.Body.BeaconBlockBodyJson = *jsonifyBeaconBlockBody(beaconBlockBody)
		signedBeaconBlockBellatrixJson.Message.Body.SyncAggregate.SyncCommitteeBits = "0x" + hex.EncodeToString(blockType.Bellatrix.Block.Body.SyncAggregate.SyncCommitteeBits)
		signedBeaconBlockBellatrixJson.Message.Body.SyncAggregate.SyncCommitteeSignature = "0x" + hex.EncodeToString(blockType.Bellatrix.Block.Body.SyncAggregate.SyncCommitteeSignature)
		signedBeaconBlockBellatrixJson.Message.Body.ExecutionPayload.BaseFeePerGas = string(blockType.Bellatrix.Block.Body.ExecutionPayload.BaseFeePerGas)
		signedBeaconBlockBellatrixJson.Message.Body.ExecutionPayload.BlockHash = "0x" + hex.EncodeToString(blockType.Bellatrix.Block.Body.ExecutionPayload.BlockHash)
		signedBeaconBlockBellatrixJson.Message.Body.ExecutionPayload.BlockNumber = strconv.FormatUint(blockType.Bellatrix.Block.Body.ExecutionPayload.BlockNumber, 10)
		signedBeaconBlockBellatrixJson.Message.Body.ExecutionPayload.ExtraData = "0x" + hex.EncodeToString(blockType.Bellatrix.Block.Body.ExecutionPayload.ExtraData)
		signedBeaconBlockBellatrixJson.Message.Body.ExecutionPayload.FeeRecipient = "0x" + hex.EncodeToString(blockType.Bellatrix.Block.Body.ExecutionPayload.FeeRecipient)
		signedBeaconBlockBellatrixJson.Message.Body.ExecutionPayload.GasLimit = strconv.FormatUint(blockType.Bellatrix.Block.Body.ExecutionPayload.GasLimit, 10)
		signedBeaconBlockBellatrixJson.Message.Body.ExecutionPayload.GasUsed = strconv.FormatUint(blockType.Bellatrix.Block.Body.ExecutionPayload.GasUsed, 10)
		signedBeaconBlockBellatrixJson.Message.Body.ExecutionPayload.LogsBloom = "0x" + hex.EncodeToString(blockType.Bellatrix.Block.Body.ExecutionPayload.LogsBloom)
		signedBeaconBlockBellatrixJson.Message.Body.ExecutionPayload.ParentHash = "0x" + hex.EncodeToString(blockType.Bellatrix.Block.Body.ExecutionPayload.ParentHash)
		signedBeaconBlockBellatrixJson.Message.Body.ExecutionPayload.PrevRandao = "0x" + hex.EncodeToString(blockType.Bellatrix.Block.Body.ExecutionPayload.PrevRandao)
		signedBeaconBlockBellatrixJson.Message.Body.ExecutionPayload.ReceiptsRoot = "0x" + hex.EncodeToString(blockType.Bellatrix.Block.Body.ExecutionPayload.ReceiptsRoot)
		signedBeaconBlockBellatrixJson.Message.Body.ExecutionPayload.StateRoot = "0x" + hex.EncodeToString(blockType.Bellatrix.Block.Body.ExecutionPayload.StateRoot)
		signedBeaconBlockBellatrixJson.Message.Body.ExecutionPayload.TimeStamp = strconv.FormatUint(blockType.Bellatrix.Block.Body.ExecutionPayload.Timestamp, 10)

		for _, transaction := range blockType.Bellatrix.Block.Body.ExecutionPayload.Transactions {
			transactionJson := "0x" + hex.EncodeToString(transaction)
			signedBeaconBlockBellatrixJson.Message.Body.ExecutionPayload.Transactions = append(signedBeaconBlockBellatrixJson.Message.Body.ExecutionPayload.Transactions, transactionJson)
		}

		marshalledSignedBeaconBlockJson, err = json.Marshal(signedBeaconBlockBellatrixJson)
		if err != nil {
			return nil, err
		}
	case *ethpb.GenericSignedBeaconBlock_BlindedBellatrix:
		blinded = true
		consensusVersion = "bellatrix"
		if len(blockType.BlindedBellatrix.Block.Body.Attestations) > 0 {
			beaconBlockRoot = blockType.BlindedBellatrix.Block.Body.Attestations[0].Data.BeaconBlockRoot
		}

		// Convert the phase0 fields of BlindedBellatrix to a BeaconBlockBody to be able to reuse jsonifyBeaconBlockBody
		beaconBlockBody := &ethpb.BeaconBlockBody{}
		signature = blockType.BlindedBellatrix.Signature
		beaconBlockBody.RandaoReveal = blockType.BlindedBellatrix.Block.Body.RandaoReveal
		beaconBlockBody.Eth1Data = blockType.BlindedBellatrix.Block.Body.Eth1Data
		beaconBlockBody.Graffiti = blockType.BlindedBellatrix.Block.Body.Graffiti
		beaconBlockBody.ProposerSlashings = blockType.BlindedBellatrix.Block.Body.ProposerSlashings
		beaconBlockBody.AttesterSlashings = blockType.BlindedBellatrix.Block.Body.AttesterSlashings
		beaconBlockBody.Attestations = blockType.BlindedBellatrix.Block.Body.Attestations
		beaconBlockBody.Deposits = blockType.BlindedBellatrix.Block.Body.Deposits
		beaconBlockBody.VoluntaryExits = blockType.BlindedBellatrix.Block.Body.VoluntaryExits
		signedBeaconBlockBellatrixJson := &SignedBlindedBeaconBlockBellatrixContainerJson{}
		signedBeaconBlockBellatrixJson.Signature = "0x" + hex.EncodeToString(signature)
		signedBeaconBlockBellatrixJson.Message.ParentRoot = "0x" + hex.EncodeToString(blockType.BlindedBellatrix.Block.ParentRoot)
		signedBeaconBlockBellatrixJson.Message.ProposerIndex = strconv.FormatUint(uint64(blockType.BlindedBellatrix.Block.ProposerIndex), 10)
		signedBeaconBlockBellatrixJson.Message.Slot = strconv.FormatUint(uint64(blockType.BlindedBellatrix.Block.Slot), 10)
		signedBeaconBlockBellatrixJson.Message.StateRoot = "0x" + hex.EncodeToString(blockType.BlindedBellatrix.Block.StateRoot)
		signedBeaconBlockBellatrixJson.Message.Body.BeaconBlockBodyJson = *jsonifyBeaconBlockBody(beaconBlockBody)
		signedBeaconBlockBellatrixJson.Message.Body.SyncAggregate.SyncCommitteeBits = "0x" + hex.EncodeToString(blockType.BlindedBellatrix.Block.Body.SyncAggregate.SyncCommitteeBits)
		signedBeaconBlockBellatrixJson.Message.Body.SyncAggregate.SyncCommitteeSignature = "0x" + hex.EncodeToString(blockType.BlindedBellatrix.Block.Body.SyncAggregate.SyncCommitteeSignature)
		signedBeaconBlockBellatrixJson.Message.Body.ExecutionPayloadHeader.BaseFeePerGas = string(blockType.BlindedBellatrix.Block.Body.ExecutionPayloadHeader.BaseFeePerGas)
		signedBeaconBlockBellatrixJson.Message.Body.ExecutionPayloadHeader.BlockHash = "0x" + hex.EncodeToString(blockType.BlindedBellatrix.Block.Body.ExecutionPayloadHeader.BlockHash)
		signedBeaconBlockBellatrixJson.Message.Body.ExecutionPayloadHeader.BlockNumber = strconv.FormatUint(blockType.BlindedBellatrix.Block.Body.ExecutionPayloadHeader.BlockNumber, 10)
		signedBeaconBlockBellatrixJson.Message.Body.ExecutionPayloadHeader.ExtraData = "0x" + hex.EncodeToString(blockType.BlindedBellatrix.Block.Body.ExecutionPayloadHeader.ExtraData)
		signedBeaconBlockBellatrixJson.Message.Body.ExecutionPayloadHeader.FeeRecipient = "0x" + hex.EncodeToString(blockType.BlindedBellatrix.Block.Body.ExecutionPayloadHeader.FeeRecipient)
		signedBeaconBlockBellatrixJson.Message.Body.ExecutionPayloadHeader.GasLimit = strconv.FormatUint(blockType.BlindedBellatrix.Block.Body.ExecutionPayloadHeader.GasLimit, 10)
		signedBeaconBlockBellatrixJson.Message.Body.ExecutionPayloadHeader.GasUsed = strconv.FormatUint(blockType.BlindedBellatrix.Block.Body.ExecutionPayloadHeader.GasUsed, 10)
		signedBeaconBlockBellatrixJson.Message.Body.ExecutionPayloadHeader.LogsBloom = "0x" + hex.EncodeToString(blockType.BlindedBellatrix.Block.Body.ExecutionPayloadHeader.LogsBloom)
		signedBeaconBlockBellatrixJson.Message.Body.ExecutionPayloadHeader.ParentHash = "0x" + hex.EncodeToString(blockType.BlindedBellatrix.Block.Body.ExecutionPayloadHeader.ParentHash)
		signedBeaconBlockBellatrixJson.Message.Body.ExecutionPayloadHeader.PrevRandao = "0x" + hex.EncodeToString(blockType.BlindedBellatrix.Block.Body.ExecutionPayloadHeader.PrevRandao)
		signedBeaconBlockBellatrixJson.Message.Body.ExecutionPayloadHeader.ReceiptsRoot = "0x" + hex.EncodeToString(blockType.BlindedBellatrix.Block.Body.ExecutionPayloadHeader.ReceiptsRoot)
		signedBeaconBlockBellatrixJson.Message.Body.ExecutionPayloadHeader.StateRoot = "0x" + hex.EncodeToString(blockType.BlindedBellatrix.Block.Body.ExecutionPayloadHeader.StateRoot)
		signedBeaconBlockBellatrixJson.Message.Body.ExecutionPayloadHeader.TimeStamp = strconv.FormatUint(blockType.BlindedBellatrix.Block.Body.ExecutionPayloadHeader.Timestamp, 10)
		signedBeaconBlockBellatrixJson.Message.Body.ExecutionPayloadHeader.TransactionsRoot = "0x" + hex.EncodeToString(blockType.BlindedBellatrix.Block.Body.ExecutionPayloadHeader.TransactionsRoot)

		marshalledSignedBeaconBlockJson, err = json.Marshal(signedBeaconBlockBellatrixJson)
		if err != nil {
			return nil, err
		}
	case *ethpb.GenericSignedBeaconBlock_BlindedCapella:
		return nil, errors.Errorf("BlindedCapella blocks are not supported yet")
	case *ethpb.GenericSignedBeaconBlock_Capella:
		return nil, errors.Errorf("Capella blocks are not supported yet")
	default:
		return nil, errors.Errorf("unsupported block type")
	}

	var url string

	if blinded {
		url = c.url + "/eth/v1/beacon/blinded_blocks"
	} else {
		url = c.url + "/eth/v1/beacon/blocks"
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(marshalledSignedBeaconBlockJson))
	req.Header.Set("Eth-Consensus-Version", consensusVersion)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err = resp.Body.Close(); err != nil {
			return
		}
	}()

	// This endpoint returns status 202 (StatusAccepted) when broadcast succeeded but block validation failed
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		errorJson := ErrorResponseJson{}
		err = json.NewDecoder(resp.Body).Decode(&errorJson)
		if err != nil {
			return nil, err
		}

		return nil, errors.Errorf("error %d: %s", errorJson.Code, errorJson.Message)
	}

	return &ethpb.ProposeResponse{BlockRoot: beaconBlockRoot}, nil
}

func jsonifyBeaconBlockBody(beaconBlockBody *ethpb.BeaconBlockBody) *BeaconBlockBodyJson {
	beaconBlockBodyJson := &BeaconBlockBodyJson{}

	for _, attestation := range beaconBlockBody.Attestations {
		attestationJson := &AttestationJson{}
		attestationJson.AggregationBits = "0x" + hex.EncodeToString(attestation.AggregationBits)
		attestationJson.Data = jsonifyAttestationData(attestation.Data)
		attestationJson.Signature = "0x" + hex.EncodeToString(attestation.Signature)
		beaconBlockBodyJson.Attestations = append(beaconBlockBodyJson.Attestations, attestationJson)
	}

	for _, attesterSlashing := range beaconBlockBody.AttesterSlashings {
		attesterSlashingJson := &AttesterSlashingJson{}
		attesterSlashingJson.Attestation_1 = jsonifyIndexedAttestation(attesterSlashing.Attestation_1)
		attesterSlashingJson.Attestation_2 = jsonifyIndexedAttestation(attesterSlashing.Attestation_2)
		beaconBlockBodyJson.AttesterSlashings = append(beaconBlockBodyJson.AttesterSlashings, attesterSlashingJson)
	}

	for _, deposit := range beaconBlockBody.Deposits {
		depositJson := &DepositJson{}
		depositJson.Data.Amount = strconv.FormatUint(deposit.Data.Amount, 10)
		depositJson.Data.PublicKey = "0x" + hex.EncodeToString(deposit.Data.PublicKey)
		depositJson.Data.Signature = "0x" + hex.EncodeToString(deposit.Data.Signature)
		depositJson.Data.WithdrawalCredentials = "0x" + hex.EncodeToString(deposit.Data.WithdrawalCredentials)
		for _, proof := range deposit.Proof {
			depositJson.Proof = append(depositJson.Proof, "0x"+hex.EncodeToString(proof))
		}
		beaconBlockBodyJson.Deposits = append(beaconBlockBodyJson.Deposits, depositJson)
	}

	beaconBlockBodyJson.Eth1Data.BlockHash = "0x" + hex.EncodeToString(beaconBlockBody.Eth1Data.BlockHash)
	beaconBlockBodyJson.Eth1Data.DepositCount = strconv.FormatUint(beaconBlockBody.Eth1Data.DepositCount, 10)
	beaconBlockBodyJson.Eth1Data.DepositRoot = "0x" + hex.EncodeToString(beaconBlockBody.Eth1Data.DepositRoot)
	beaconBlockBodyJson.Graffiti = string(beaconBlockBody.Graffiti)

	for _, proposerSlashing := range beaconBlockBody.ProposerSlashings {
		proposerSlashingJson := &ProposerSlashingJson{}
		proposerSlashingJson.Header_1 = jsonifySignedBeaconBlockHeader(proposerSlashing.Header_1)
		proposerSlashingJson.Header_2 = jsonifySignedBeaconBlockHeader(proposerSlashing.Header_2)
		beaconBlockBodyJson.ProposerSlashings = append(beaconBlockBodyJson.ProposerSlashings, proposerSlashingJson)
	}

	beaconBlockBodyJson.RandaoReveal = "0x" + hex.EncodeToString(beaconBlockBody.RandaoReveal)

	for _, signedVoluntaryExit := range beaconBlockBody.VoluntaryExits {
		signedVoluntaryExitJson := &SignedVoluntaryExitJson{}
		signedVoluntaryExitJson.Exit.Epoch = strconv.FormatUint(uint64(signedVoluntaryExit.Exit.Epoch), 10)
		signedVoluntaryExitJson.Exit.ValidatorIndex = strconv.FormatUint(uint64(signedVoluntaryExit.Exit.ValidatorIndex), 10)
		signedVoluntaryExitJson.Signature = "0x" + hex.EncodeToString(signedVoluntaryExit.Signature)
		beaconBlockBodyJson.VoluntaryExits = append(beaconBlockBodyJson.VoluntaryExits, signedVoluntaryExitJson)
	}

	return beaconBlockBodyJson
}

func jsonifyAttestationData(attestationData *ethpb.AttestationData) *AttestationDataJson {
	attestationDataJson := &AttestationDataJson{}
	attestationDataJson.BeaconBlockRoot = "0x" + hex.EncodeToString(attestationData.BeaconBlockRoot)
	attestationDataJson.CommitteeIndex = strconv.FormatUint(uint64(attestationData.CommitteeIndex), 10)
	attestationDataJson.Slot = strconv.FormatUint(uint64(attestationData.Slot), 10)
	attestationDataJson.Source.Epoch = strconv.FormatUint(uint64(attestationData.Source.Epoch), 10)
	attestationDataJson.Source.Root = "0x" + hex.EncodeToString(attestationData.Source.Root)
	attestationDataJson.Target.Epoch = strconv.FormatUint(uint64(attestationData.Target.Epoch), 10)
	attestationDataJson.Target.Root = "0x" + hex.EncodeToString(attestationData.Target.Root)
	return attestationDataJson
}

func jsonifyIndexedAttestation(indexedAttestation *ethpb.IndexedAttestation) *IndexedAttestationJson {
	indexedAttestationJson := &IndexedAttestationJson{}
	for _, attestingIndex := range indexedAttestation.AttestingIndices {
		attestingIndex := strconv.FormatUint(attestingIndex, 10)
		indexedAttestationJson.AttestingIndices = append(indexedAttestationJson.AttestingIndices, attestingIndex)
	}
	indexedAttestationJson.Data = jsonifyAttestationData(indexedAttestation.Data)
	indexedAttestationJson.Signature = "0x" + hex.EncodeToString(indexedAttestation.Signature)
	return indexedAttestationJson
}

func jsonifySignedBeaconBlockHeader(signedBeaconBlockHeader *ethpb.SignedBeaconBlockHeader) *SignedBeaconBlockHeaderJson {
	signedBeaconBlockHeaderJson := &SignedBeaconBlockHeaderJson{}
	signedBeaconBlockHeaderJson.Header.BodyRoot = "0x" + hex.EncodeToString(signedBeaconBlockHeader.Header.BodyRoot)
	signedBeaconBlockHeaderJson.Header.ParentRoot = "0x" + hex.EncodeToString(signedBeaconBlockHeader.Header.ParentRoot)
	signedBeaconBlockHeaderJson.Header.ProposerIndex = strconv.FormatUint(uint64(signedBeaconBlockHeader.Header.ProposerIndex), 10)
	signedBeaconBlockHeaderJson.Header.Slot = strconv.FormatUint(uint64(signedBeaconBlockHeader.Header.Slot), 10)
	signedBeaconBlockHeaderJson.Header.StateRoot = "0x" + hex.EncodeToString(signedBeaconBlockHeader.Header.StateRoot)
	signedBeaconBlockHeaderJson.Signature = "0x" + hex.EncodeToString(signedBeaconBlockHeader.Signature)
	return signedBeaconBlockHeaderJson
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
	genesis, err := c.getGenesis()
	if err != nil {
		return nil, err
	}

	genesisTime, err := strconv.ParseUint(genesis.Data.GenesisTime, 10, 64)
	if err != nil {
		return nil, err
	}

	chainStartResponse := &ethpb.ChainStartResponse{}
	chainStartResponse.Started = true
	chainStartResponse.GenesisTime = genesisTime

	// Remove the leading 0x from the string before decoding it to bytes
	genesisValidatorRoot, err := hex.DecodeString(genesis.Data.GenesisValidatorsRoot[2:])
	if err != nil {
		return nil, err
	}
	chainStartResponse.GenesisValidatorsRoot = genesisValidatorRoot

	return chainStartResponse, nil
}

func (c *beaconApiValidatorClient) getGenesis() (*GenesisResponseJson, error) {
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

	genesisJson := &GenesisResponseJson{}
	err = json.NewDecoder(resp.Body).Decode(&genesisJson)
	if err != nil {
		return nil, err
	}

	return genesisJson, nil
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

	// Get the attester duties
	attesterDutiesJson, err := c.getAttesterDuties(epoch, validatorStringIndices)
	if err != nil {
		return nil, err
	}

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
	proposerDutiesJson, err := c.getProposerDuties(epoch)
	if err != nil {
		return nil, err
	}

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
	forkVersion, err := c.getForkVersion()
	if err != nil {
		return nil, err
	}

	// Phase0 doesn't have sync committees
	if forkVersion != "phase0" {
		syncDutiesJson, err := c.getSyncDuties(epoch, validatorStringIndices)
		if err != nil {
			return nil, err
		}

		for _, dutyData := range syncDutiesJson.Data {
			validatorIndex, err := strconv.ParseUint(dutyData.ValidatorIndex, 10, 64)
			if err != nil {
				return nil, err
			}

			if dutyResponse, exists := indicesMapping[validatorIndex]; exists {
				dutyResponse.PublicKey = []byte(dutyData.Pubkey)
				dutyResponse.IsSyncCommittee = true

				for indexInCommittee, committeeValidatorIndex := range dutyData.ValidatorSyncCommitteeIndices {
					uintCommitteeValidatorIndex, err := strconv.ParseUint(committeeValidatorIndex, 10, 64)
					if err != nil {
						return nil, err
					}

					// Set the index of the validator in the committee array
					if uintCommitteeValidatorIndex == validatorIndex {
						dutyResponse.CommitteeIndex = types.CommitteeIndex(indexInCommittee)
					}

					dutyResponse.Committee = append(dutyResponse.Committee, types.ValidatorIndex(uintCommitteeValidatorIndex))
				}
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

func (c *beaconApiValidatorClient) getForkVersion() (string, error) {
	// Query the last block to get the fork version
	resp, err := c.httpClient.Get(c.url + "/eth/v2/beacon/blocks/head")
	if err != nil {
		return "", err
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
			return "", err
		}

		return "", errors.Errorf("error %d: %s", errorJson.Code, errorJson.Message)
	}

	blockV2ResponseJson := BlockV2ResponseJson{}
	err = json.NewDecoder(resp.Body).Decode(&blockV2ResponseJson)
	if err != nil {
		return "", err
	}

	return blockV2ResponseJson.Version, nil
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
