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
	"github.com/prysmaticlabs/prysm/v3/beacon-chain/rpc/apimiddleware"
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
		errorJson := apimiddleware.EventErrorJson{}
		err = json.NewDecoder(resp.Body).Decode(&errorJson)
		if err != nil {
			return nil, err
		}

		return nil, errors.Errorf("error %d: %s", errorJson.StatusCode, errorJson.Message)
	}

	blockAttestationsResponseJson := apimiddleware.BlockAttestationsResponseJson{}
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

		signedBeaconBlockJson := &apimiddleware.SignedBeaconBlockContainerJson{
			Signature: "0x" + hex.EncodeToString(blockType.Phase0.Signature),
			Message: &apimiddleware.BeaconBlockJson{
				Body:          jsonifyBeaconBlockBody(blockType.Phase0.Block.Body),
				ParentRoot:    "0x" + hex.EncodeToString(blockType.Phase0.Block.ParentRoot),
				ProposerIndex: strconv.FormatUint(uint64(blockType.Phase0.Block.ProposerIndex), 10),
				Slot:          strconv.FormatUint(uint64(blockType.Phase0.Block.Slot), 10),
				StateRoot:     "0x" + hex.EncodeToString(blockType.Phase0.Block.StateRoot),
			},
		}

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
		phase0BeaconBlockBody := &ethpb.BeaconBlockBody{
			RandaoReveal:      blockType.Altair.Block.Body.RandaoReveal,
			Eth1Data:          blockType.Altair.Block.Body.Eth1Data,
			Graffiti:          blockType.Altair.Block.Body.Graffiti,
			ProposerSlashings: blockType.Altair.Block.Body.ProposerSlashings,
			AttesterSlashings: blockType.Altair.Block.Body.AttesterSlashings,
			Attestations:      blockType.Altair.Block.Body.Attestations,
			Deposits:          blockType.Altair.Block.Body.Deposits,
			VoluntaryExits:    blockType.Altair.Block.Body.VoluntaryExits,
		}
		phase0BeaconBlockBodyJson := jsonifyBeaconBlockBody(phase0BeaconBlockBody)

		signedBeaconBlockAltairJson := &apimiddleware.SignedBeaconBlockAltairContainerJson{
			Signature: "0x" + hex.EncodeToString(blockType.Altair.Signature),
			Message: &apimiddleware.BeaconBlockAltairJson{
				ParentRoot:    "0x" + hex.EncodeToString(blockType.Altair.Block.ParentRoot),
				ProposerIndex: strconv.FormatUint(uint64(blockType.Altair.Block.ProposerIndex), 10),
				Slot:          strconv.FormatUint(uint64(blockType.Altair.Block.Slot), 10),
				StateRoot:     "0x" + hex.EncodeToString(blockType.Altair.Block.StateRoot),
				Body: &apimiddleware.BeaconBlockBodyAltairJson{
					// Set the phase0 fields
					Attestations:      phase0BeaconBlockBodyJson.Attestations,
					AttesterSlashings: phase0BeaconBlockBodyJson.AttesterSlashings,
					Deposits:          phase0BeaconBlockBodyJson.Deposits,
					Eth1Data:          phase0BeaconBlockBodyJson.Eth1Data,
					Graffiti:          phase0BeaconBlockBodyJson.Graffiti,
					ProposerSlashings: phase0BeaconBlockBodyJson.ProposerSlashings,
					RandaoReveal:      phase0BeaconBlockBodyJson.RandaoReveal,
					VoluntaryExits:    phase0BeaconBlockBodyJson.VoluntaryExits,
					// Set the altair fields
					SyncAggregate: &apimiddleware.SyncAggregateJson{
						SyncCommitteeBits:      "0x" + hex.EncodeToString(blockType.Altair.Block.Body.SyncAggregate.SyncCommitteeBits),
						SyncCommitteeSignature: "0x" + hex.EncodeToString(blockType.Altair.Block.Body.SyncAggregate.SyncCommitteeSignature),
					},
				},
			},
		}

		marshalledSignedBeaconBlockJson, err = json.Marshal(signedBeaconBlockAltairJson)
		if err != nil {
			return nil, err
		}
	case *ethpb.GenericSignedBeaconBlock_Bellatrix:
		consensusVersion = "bellatrix"
		if len(blockType.Bellatrix.Block.Body.Attestations) > 0 {
			beaconBlockRoot = blockType.Bellatrix.Block.Body.Attestations[0].Data.BeaconBlockRoot
		}

		// Gather the transactions
		var executionPayloadTransaction []string
		for _, transaction := range blockType.Bellatrix.Block.Body.ExecutionPayload.Transactions {
			transactionJson := "0x" + hex.EncodeToString(transaction)
			executionPayloadTransaction = append(executionPayloadTransaction, transactionJson)
		}

		// Convert the phase0 fields of Bellatrix to a BeaconBlockBody to be able to reuse jsonifyBeaconBlockBody
		phase0BeaconBlockBody := &ethpb.BeaconBlockBody{
			RandaoReveal:      blockType.Bellatrix.Block.Body.RandaoReveal,
			Eth1Data:          blockType.Bellatrix.Block.Body.Eth1Data,
			Graffiti:          blockType.Bellatrix.Block.Body.Graffiti,
			ProposerSlashings: blockType.Bellatrix.Block.Body.ProposerSlashings,
			AttesterSlashings: blockType.Bellatrix.Block.Body.AttesterSlashings,
			Attestations:      blockType.Bellatrix.Block.Body.Attestations,
			Deposits:          blockType.Bellatrix.Block.Body.Deposits,
			VoluntaryExits:    blockType.Bellatrix.Block.Body.VoluntaryExits,
		}
		phase0BeaconBlockBodyJson := jsonifyBeaconBlockBody(phase0BeaconBlockBody)

		signedBeaconBlockBellatrixJson := &apimiddleware.SignedBeaconBlockBellatrixContainerJson{
			Signature: "0x" + hex.EncodeToString(blockType.Bellatrix.Signature),
			Message: &apimiddleware.BeaconBlockBellatrixJson{
				ParentRoot:    "0x" + hex.EncodeToString(blockType.Bellatrix.Block.ParentRoot),
				ProposerIndex: strconv.FormatUint(uint64(blockType.Bellatrix.Block.ProposerIndex), 10),
				Slot:          strconv.FormatUint(uint64(blockType.Bellatrix.Block.Slot), 10),
				StateRoot:     "0x" + hex.EncodeToString(blockType.Bellatrix.Block.StateRoot),
				Body: &apimiddleware.BeaconBlockBodyBellatrixJson{
					// Set the phase0 fields
					Attestations:      phase0BeaconBlockBodyJson.Attestations,
					AttesterSlashings: phase0BeaconBlockBodyJson.AttesterSlashings,
					Deposits:          phase0BeaconBlockBodyJson.Deposits,
					Eth1Data:          phase0BeaconBlockBodyJson.Eth1Data,
					Graffiti:          phase0BeaconBlockBodyJson.Graffiti,
					ProposerSlashings: phase0BeaconBlockBodyJson.ProposerSlashings,
					RandaoReveal:      phase0BeaconBlockBodyJson.RandaoReveal,
					VoluntaryExits:    phase0BeaconBlockBodyJson.VoluntaryExits,
					// Set the altair fields
					SyncAggregate: &apimiddleware.SyncAggregateJson{
						SyncCommitteeBits:      "0x" + hex.EncodeToString(blockType.Bellatrix.Block.Body.SyncAggregate.SyncCommitteeBits),
						SyncCommitteeSignature: "0x" + hex.EncodeToString(blockType.Bellatrix.Block.Body.SyncAggregate.SyncCommitteeSignature),
					},
					// Set the bellatrix fields
					ExecutionPayload: &apimiddleware.ExecutionPayloadJson{
						BaseFeePerGas: string(blockType.Bellatrix.Block.Body.ExecutionPayload.BaseFeePerGas),
						BlockHash:     "0x" + hex.EncodeToString(blockType.Bellatrix.Block.Body.ExecutionPayload.BlockHash),
						BlockNumber:   strconv.FormatUint(blockType.Bellatrix.Block.Body.ExecutionPayload.BlockNumber, 10),
						ExtraData:     "0x" + hex.EncodeToString(blockType.Bellatrix.Block.Body.ExecutionPayload.ExtraData),
						FeeRecipient:  "0x" + hex.EncodeToString(blockType.Bellatrix.Block.Body.ExecutionPayload.FeeRecipient),
						GasLimit:      strconv.FormatUint(blockType.Bellatrix.Block.Body.ExecutionPayload.GasLimit, 10),
						GasUsed:       strconv.FormatUint(blockType.Bellatrix.Block.Body.ExecutionPayload.GasUsed, 10),
						LogsBloom:     "0x" + hex.EncodeToString(blockType.Bellatrix.Block.Body.ExecutionPayload.LogsBloom),
						ParentHash:    "0x" + hex.EncodeToString(blockType.Bellatrix.Block.Body.ExecutionPayload.ParentHash),
						PrevRandao:    "0x" + hex.EncodeToString(blockType.Bellatrix.Block.Body.ExecutionPayload.PrevRandao),
						ReceiptsRoot:  "0x" + hex.EncodeToString(blockType.Bellatrix.Block.Body.ExecutionPayload.ReceiptsRoot),
						StateRoot:     "0x" + hex.EncodeToString(blockType.Bellatrix.Block.Body.ExecutionPayload.StateRoot),
						TimeStamp:     strconv.FormatUint(blockType.Bellatrix.Block.Body.ExecutionPayload.Timestamp, 10),
						Transactions:  executionPayloadTransaction,
					},
				},
			},
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
		phase0BeaconBlockBody := &ethpb.BeaconBlockBody{
			RandaoReveal:      blockType.BlindedBellatrix.Block.Body.RandaoReveal,
			Eth1Data:          blockType.BlindedBellatrix.Block.Body.Eth1Data,
			Graffiti:          blockType.BlindedBellatrix.Block.Body.Graffiti,
			ProposerSlashings: blockType.BlindedBellatrix.Block.Body.ProposerSlashings,
			AttesterSlashings: blockType.BlindedBellatrix.Block.Body.AttesterSlashings,
			Attestations:      blockType.BlindedBellatrix.Block.Body.Attestations,
			Deposits:          blockType.BlindedBellatrix.Block.Body.Deposits,
			VoluntaryExits:    blockType.BlindedBellatrix.Block.Body.VoluntaryExits,
		}
		phase0BeaconBlockBodyJson := jsonifyBeaconBlockBody(phase0BeaconBlockBody)

		signedBeaconBlockBellatrixJson := &apimiddleware.SignedBlindedBeaconBlockBellatrixContainerJson{
			Signature: "0x" + hex.EncodeToString(blockType.BlindedBellatrix.Signature),
			Message: &apimiddleware.BlindedBeaconBlockBellatrixJson{
				ParentRoot:    "0x" + hex.EncodeToString(blockType.BlindedBellatrix.Block.ParentRoot),
				ProposerIndex: strconv.FormatUint(uint64(blockType.BlindedBellatrix.Block.ProposerIndex), 10),
				Slot:          strconv.FormatUint(uint64(blockType.BlindedBellatrix.Block.Slot), 10),
				StateRoot:     "0x" + hex.EncodeToString(blockType.BlindedBellatrix.Block.StateRoot),
				Body: &apimiddleware.BlindedBeaconBlockBodyBellatrixJson{
					// Set the phase0 fields
					Attestations:      phase0BeaconBlockBodyJson.Attestations,
					AttesterSlashings: phase0BeaconBlockBodyJson.AttesterSlashings,
					Deposits:          phase0BeaconBlockBodyJson.Deposits,
					Eth1Data:          phase0BeaconBlockBodyJson.Eth1Data,
					Graffiti:          phase0BeaconBlockBodyJson.Graffiti,
					ProposerSlashings: phase0BeaconBlockBodyJson.ProposerSlashings,
					RandaoReveal:      phase0BeaconBlockBodyJson.RandaoReveal,
					VoluntaryExits:    phase0BeaconBlockBodyJson.VoluntaryExits,
					// Set the altair fields
					SyncAggregate: &apimiddleware.SyncAggregateJson{
						SyncCommitteeBits:      "0x" + hex.EncodeToString(blockType.BlindedBellatrix.Block.Body.SyncAggregate.SyncCommitteeBits),
						SyncCommitteeSignature: "0x" + hex.EncodeToString(blockType.BlindedBellatrix.Block.Body.SyncAggregate.SyncCommitteeSignature),
					},
					// Set the bellatrix fields
					ExecutionPayloadHeader: &apimiddleware.ExecutionPayloadHeaderJson{
						BaseFeePerGas:    string(blockType.BlindedBellatrix.Block.Body.ExecutionPayloadHeader.BaseFeePerGas),
						BlockHash:        "0x" + hex.EncodeToString(blockType.BlindedBellatrix.Block.Body.ExecutionPayloadHeader.BlockHash),
						BlockNumber:      strconv.FormatUint(blockType.BlindedBellatrix.Block.Body.ExecutionPayloadHeader.BlockNumber, 10),
						ExtraData:        "0x" + hex.EncodeToString(blockType.BlindedBellatrix.Block.Body.ExecutionPayloadHeader.ExtraData),
						FeeRecipient:     "0x" + hex.EncodeToString(blockType.BlindedBellatrix.Block.Body.ExecutionPayloadHeader.FeeRecipient),
						GasLimit:         strconv.FormatUint(blockType.BlindedBellatrix.Block.Body.ExecutionPayloadHeader.GasLimit, 10),
						GasUsed:          strconv.FormatUint(blockType.BlindedBellatrix.Block.Body.ExecutionPayloadHeader.GasUsed, 10),
						LogsBloom:        "0x" + hex.EncodeToString(blockType.BlindedBellatrix.Block.Body.ExecutionPayloadHeader.LogsBloom),
						ParentHash:       "0x" + hex.EncodeToString(blockType.BlindedBellatrix.Block.Body.ExecutionPayloadHeader.ParentHash),
						PrevRandao:       "0x" + hex.EncodeToString(blockType.BlindedBellatrix.Block.Body.ExecutionPayloadHeader.PrevRandao),
						ReceiptsRoot:     "0x" + hex.EncodeToString(blockType.BlindedBellatrix.Block.Body.ExecutionPayloadHeader.ReceiptsRoot),
						StateRoot:        "0x" + hex.EncodeToString(blockType.BlindedBellatrix.Block.Body.ExecutionPayloadHeader.StateRoot),
						TimeStamp:        strconv.FormatUint(blockType.BlindedBellatrix.Block.Body.ExecutionPayloadHeader.Timestamp, 10),
						TransactionsRoot: "0x" + hex.EncodeToString(blockType.BlindedBellatrix.Block.Body.ExecutionPayloadHeader.TransactionsRoot),
					},
				},
			},
		}

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
		errorJson := apimiddleware.EventErrorJson{}
		err = json.NewDecoder(resp.Body).Decode(&errorJson)
		if err != nil {
			return nil, err
		}

		return nil, errors.Errorf("error %d: %s", errorJson.StatusCode, errorJson.Message)
	}

	return &ethpb.ProposeResponse{BlockRoot: beaconBlockRoot}, nil
}

func jsonifyBeaconBlockBody(beaconBlockBody *ethpb.BeaconBlockBody) *apimiddleware.BeaconBlockBodyJson {
	var attestations []*apimiddleware.AttestationJson
	for _, attestation := range beaconBlockBody.Attestations {
		attestationJson := &apimiddleware.AttestationJson{
			AggregationBits: "0x" + hex.EncodeToString(attestation.AggregationBits),
			Data:            jsonifyAttestationData(attestation.Data),
			Signature:       "0x" + hex.EncodeToString(attestation.Signature),
		}
		attestations = append(attestations, attestationJson)
	}

	var attesterSlashings []*apimiddleware.AttesterSlashingJson
	for _, attesterSlashing := range beaconBlockBody.AttesterSlashings {
		attesterSlashingJson := &apimiddleware.AttesterSlashingJson{
			Attestation_1: jsonifyIndexedAttestation(attesterSlashing.Attestation_1),
			Attestation_2: jsonifyIndexedAttestation(attesterSlashing.Attestation_2),
		}
		attesterSlashings = append(attesterSlashings, attesterSlashingJson)
	}

	var deposits []*apimiddleware.DepositJson
	for _, deposit := range beaconBlockBody.Deposits {
		var proofs []string
		for _, proof := range deposit.Proof {
			proofs = append(proofs, "0x"+hex.EncodeToString(proof))
		}

		depositJson := &apimiddleware.DepositJson{
			Data: &apimiddleware.Deposit_DataJson{
				Amount:                strconv.FormatUint(deposit.Data.Amount, 10),
				PublicKey:             "0x" + hex.EncodeToString(deposit.Data.PublicKey),
				Signature:             "0x" + hex.EncodeToString(deposit.Data.Signature),
				WithdrawalCredentials: "0x" + hex.EncodeToString(deposit.Data.WithdrawalCredentials),
			},
			Proof: proofs,
		}
		deposits = append(deposits, depositJson)
	}

	var proposerSlashings []*apimiddleware.ProposerSlashingJson
	for _, proposerSlashing := range beaconBlockBody.ProposerSlashings {
		proposerSlashingJson := &apimiddleware.ProposerSlashingJson{
			Header_1: jsonifySignedBeaconBlockHeader(proposerSlashing.Header_1),
			Header_2: jsonifySignedBeaconBlockHeader(proposerSlashing.Header_2),
		}
		proposerSlashings = append(proposerSlashings, proposerSlashingJson)
	}

	var signedVoluntaryExits []*apimiddleware.SignedVoluntaryExitJson
	for _, signedVoluntaryExit := range beaconBlockBody.VoluntaryExits {
		signedVoluntaryExitJson := &apimiddleware.SignedVoluntaryExitJson{
			Exit: &apimiddleware.VoluntaryExitJson{
				Epoch:          strconv.FormatUint(uint64(signedVoluntaryExit.Exit.Epoch), 10),
				ValidatorIndex: strconv.FormatUint(uint64(signedVoluntaryExit.Exit.ValidatorIndex), 10),
			},
			Signature: "0x" + hex.EncodeToString(signedVoluntaryExit.Signature),
		}
		signedVoluntaryExits = append(signedVoluntaryExits, signedVoluntaryExitJson)
	}

	beaconBlockBodyJson := &apimiddleware.BeaconBlockBodyJson{
		Attestations:      attestations,
		AttesterSlashings: attesterSlashings,
		Deposits:          deposits,
		Eth1Data: &apimiddleware.Eth1DataJson{
			BlockHash:    "0x" + hex.EncodeToString(beaconBlockBody.Eth1Data.BlockHash),
			DepositCount: strconv.FormatUint(beaconBlockBody.Eth1Data.DepositCount, 10),
			DepositRoot:  "0x" + hex.EncodeToString(beaconBlockBody.Eth1Data.DepositRoot),
		},
		Graffiti:          string(beaconBlockBody.Graffiti),
		ProposerSlashings: proposerSlashings,
		RandaoReveal:      "0x" + hex.EncodeToString(beaconBlockBody.RandaoReveal),
		VoluntaryExits:    signedVoluntaryExits,
	}

	return beaconBlockBodyJson
}

func jsonifyAttestationData(attestationData *ethpb.AttestationData) *apimiddleware.AttestationDataJson {
	attestationDataJson := &apimiddleware.AttestationDataJson{}
	attestationDataJson.BeaconBlockRoot = "0x" + hex.EncodeToString(attestationData.BeaconBlockRoot)
	attestationDataJson.CommitteeIndex = strconv.FormatUint(uint64(attestationData.CommitteeIndex), 10)
	attestationDataJson.Slot = strconv.FormatUint(uint64(attestationData.Slot), 10)
	attestationDataJson.Source.Epoch = strconv.FormatUint(uint64(attestationData.Source.Epoch), 10)
	attestationDataJson.Source.Root = "0x" + hex.EncodeToString(attestationData.Source.Root)
	attestationDataJson.Target.Epoch = strconv.FormatUint(uint64(attestationData.Target.Epoch), 10)
	attestationDataJson.Target.Root = "0x" + hex.EncodeToString(attestationData.Target.Root)
	return attestationDataJson
}

func jsonifyIndexedAttestation(indexedAttestation *ethpb.IndexedAttestation) *apimiddleware.IndexedAttestationJson {
	indexedAttestationJson := &apimiddleware.IndexedAttestationJson{}
	for _, attestingIndex := range indexedAttestation.AttestingIndices {
		attestingIndex := strconv.FormatUint(attestingIndex, 10)
		indexedAttestationJson.AttestingIndices = append(indexedAttestationJson.AttestingIndices, attestingIndex)
	}
	indexedAttestationJson.Data = jsonifyAttestationData(indexedAttestation.Data)
	indexedAttestationJson.Signature = "0x" + hex.EncodeToString(indexedAttestation.Signature)
	return indexedAttestationJson
}

func jsonifySignedBeaconBlockHeader(signedBeaconBlockHeader *ethpb.SignedBeaconBlockHeader) *apimiddleware.SignedBeaconBlockHeaderJson {
	signedBeaconBlockHeaderJson := &apimiddleware.SignedBeaconBlockHeaderJson{}
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

func (c *beaconApiValidatorClient) getGenesis() (*apimiddleware.GenesisResponseJson, error) {
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
		errorJson := apimiddleware.EventErrorJson{}
		err = json.NewDecoder(resp.Body).Decode(&errorJson)
		if err != nil {
			return nil, err
		}

		return nil, errors.Errorf("error %d: %s", errorJson.StatusCode, errorJson.Message)
	}

	genesisJson := &apimiddleware.GenesisResponseJson{}
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
		errorJson := apimiddleware.EventErrorJson{}
		err = json.NewDecoder(resp.Body).Decode(&errorJson)
		if err != nil {
			return nil, err
		}

		return nil, errors.Errorf("error %d: %s", errorJson.StatusCode, errorJson.Message)
	}

	responseJson := &apimiddleware.StateValidatorResponseJson{}
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
		errorJson := apimiddleware.EventErrorJson{}
		err = json.NewDecoder(resp.Body).Decode(&errorJson)
		if err != nil {
			return nil, err
		}

		return nil, errors.Errorf("error %d: %s", errorJson.StatusCode, errorJson.Message)
	}

	responseJson := &apimiddleware.StateValidatorsResponseJson{}
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
func (c *beaconApiValidatorClient) getActivationQueue() (*apimiddleware.StateValidatorsResponseJson, error) {
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
		errorJson := apimiddleware.EventErrorJson{}
		err = json.NewDecoder(resp.Body).Decode(&errorJson)
		if err != nil {
			return nil, err
		}

		return nil, errors.Errorf("error %d: %s", errorJson.StatusCode, errorJson.Message)
	}

	responseJson := &apimiddleware.StateValidatorsResponseJson{}
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

func (c *beaconApiValidatorClient) getAttesterDuties(epoch uint64, validatorIndices []string) (*apimiddleware.AttesterDutiesResponseJson, error) {
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
		errorJson := apimiddleware.EventErrorJson{}
		err = json.NewDecoder(resp.Body).Decode(&errorJson)
		if err != nil {
			return nil, err
		}

		return nil, errors.Errorf("error %d: %s", errorJson.StatusCode, errorJson.Message)
	}

	dutiesJson := &apimiddleware.AttesterDutiesResponseJson{}
	err = json.NewDecoder(resp.Body).Decode(&dutiesJson)
	if err != nil {
		return nil, err
	}

	return dutiesJson, nil
}

func (c *beaconApiValidatorClient) getProposerDuties(epoch uint64) (*apimiddleware.ProposerDutiesResponseJson, error) {
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
		errorJson := apimiddleware.EventErrorJson{}
		err = json.NewDecoder(resp.Body).Decode(&errorJson)
		if err != nil {
			return nil, err
		}

		return nil, errors.Errorf("error %d: %s", errorJson.StatusCode, errorJson.Message)
	}

	dutiesJson := &apimiddleware.ProposerDutiesResponseJson{}
	err = json.NewDecoder(resp.Body).Decode(&dutiesJson)
	if err != nil {
		return nil, err
	}

	return dutiesJson, nil
}

func (c *beaconApiValidatorClient) getSyncDuties(epoch uint64, validatorIndices []string) (*apimiddleware.SyncCommitteeDutiesResponseJson, error) {
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
		errorJson := apimiddleware.EventErrorJson{}
		err = json.NewDecoder(resp.Body).Decode(&errorJson)
		if err != nil {
			return nil, err
		}

		return nil, errors.Errorf("error %d: %s", errorJson.StatusCode, errorJson.Message)
	}

	dutiesJson := &apimiddleware.SyncCommitteeDutiesResponseJson{}
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
		errorJson := apimiddleware.EventErrorJson{}
		err = json.NewDecoder(resp.Body).Decode(&errorJson)
		if err != nil {
			return "", err
		}

		return "", errors.Errorf("error %d: %s", errorJson.StatusCode, errorJson.Message)
	}

	blockV2ResponseJson := apimiddleware.BlockV2ResponseJson{}
	err = json.NewDecoder(resp.Body).Decode(&blockV2ResponseJson)
	if err != nil {
		return "", err
	}

	return blockV2ResponseJson.Version, nil
}

func parseValidatorStatusResponse(responseData *apimiddleware.ValidatorContainerJson, activationQueue *apimiddleware.StateValidatorsResponseJson) (*ethpb.ValidatorStatusResponse, error) {
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
