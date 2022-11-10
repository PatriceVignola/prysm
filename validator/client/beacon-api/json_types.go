//go:build use_beacon_api
// +build use_beacon_api

package beacon_api

type ErrorResponseJson struct {
	Code    int    `json:"status_code"`
	Message string `json:"message"`
}

type GenesisResponseJson struct {
	Data struct {
		GenesisTime           string `json:"genesis_time" time:"true"`
		GenesisValidatorsRoot string `json:"genesis_validators_root" hex:"true"`
		GenesisForkVersion    string `json:"genesis_fork_version" hex:"true"`
	} `json:"data"`
}

type AttesterDutiesResponseJson struct {
	DependentRoot string `json:"dependent_root" hex:"true"`
	Data          []struct {
		Pubkey                  string `json:"pubkey" hex:"true"`
		ValidatorIndex          string `json:"validator_index"`
		CommitteeIndex          string `json:"committee_index"`
		CommitteeLength         string `json:"committee_length"`
		CommitteesAtSlot        string `json:"committees_at_slot"`
		ValidatorCommitteeIndex string `json:"validator_committee_index"`
		Slot                    string `json:"slot"`
	} `json:"data"`
	ExecutionOptimistic bool `json:"execution_optimistic"`
}

type ProposerDutiesResponseJson struct {
	DependentRoot string `json:"dependent_root" hex:"true"`
	Data          []struct {
		Pubkey         string `json:"pubkey" hex:"true"`
		ValidatorIndex string `json:"validator_index"`
		Slot           string `json:"slot"`
	} `json:"data"`
	ExecutionOptimistic bool `json:"execution_optimistic"`
}

type SyncCommitteeDutiesResponseJson struct {
	Data []struct {
		Pubkey                        string   `json:"pubkey" hex:"true"`
		ValidatorIndex                string   `json:"validator_index"`
		ValidatorSyncCommitteeIndices []string `json:"validator_sync_committee_indices"`
	} `json:"data"`
	ExecutionOptimistic bool `json:"execution_optimistic"`
}

type ValidatorJson struct {
	PublicKey                  string `json:"pubkey" hex:"true"`
	WithdrawalCredentials      string `json:"withdrawal_credentials" hex:"true"`
	EffectiveBalance           string `json:"effective_balance"`
	Slashed                    bool   `json:"slashed"`
	ActivationEligibilityEpoch string `json:"activation_eligibility_epoch"`
	ActivationEpoch            string `json:"activation_epoch"`
	ExitEpoch                  string `json:"exit_epoch"`
	WithdrawableEpoch          string `json:"withdrawable_epoch"`
}

type ValidatorContainerJson struct {
	Index     string         `json:"index"`
	Balance   string         `json:"balance"`
	Status    string         `json:"status" enum:"true"`
	Validator *ValidatorJson `json:"validator"`
}

type StateValidatorsResponseJson struct {
	Data                []*ValidatorContainerJson `json:"data"`
	ExecutionOptimistic bool                      `json:"execution_optimistic"`
}

type StateValidatorResponseJson struct {
	Data                *ValidatorContainerJson `json:"data"`
	ExecutionOptimistic bool                    `json:"execution_optimistic"`
}

type BeaconBlockBodyJson struct {
	RandaoReveal      string                     `json:"randao_reveal" hex:"true"`
	Eth1Data          *Eth1DataJson              `json:"eth1_data"`
	Graffiti          string                     `json:"graffiti" hex:"true"`
	ProposerSlashings []*ProposerSlashingJson    `json:"proposer_slashings"`
	AttesterSlashings []*AttesterSlashingJson    `json:"attester_slashings"`
	Attestations      []*AttestationJson         `json:"attestations"`
	Deposits          []*DepositJson             `json:"deposits"`
	VoluntaryExits    []*SignedVoluntaryExitJson `json:"voluntary_exits"`
}

type BeaconBlockJson struct {
	Slot          string               `json:"slot"`
	ProposerIndex string               `json:"proposer_index"`
	ParentRoot    string               `json:"parent_root" hex:"true"`
	StateRoot     string               `json:"state_root" hex:"true"`
	Body          *BeaconBlockBodyJson `json:"body"`
}

type BeaconBlockAltairJson struct {
	Slot          string                     `json:"slot"`
	ProposerIndex string                     `json:"proposer_index"`
	ParentRoot    string                     `json:"parent_root" hex:"true"`
	StateRoot     string                     `json:"state_root" hex:"true"`
	Body          *BeaconBlockBodyAltairJson `json:"body"`
}

type Eth1DataJson struct {
	DepositRoot  string `json:"deposit_root" hex:"true"`
	DepositCount string `json:"deposit_count"`
	BlockHash    string `json:"block_hash" hex:"true"`
}

type BeaconBlockHeaderJson struct {
	Slot          string `json:"slot"`
	ProposerIndex string `json:"proposer_index"`
	ParentRoot    string `json:"parent_root" hex:"true"`
	StateRoot     string `json:"state_root" hex:"true"`
	BodyRoot      string `json:"body_root" hex:"true"`
}

type SignedBeaconBlockHeaderJson struct {
	Header    *BeaconBlockHeaderJson `json:"message"`
	Signature string                 `json:"signature" hex:"true"`
}

type ProposerSlashingJson struct {
	Header_1 *SignedBeaconBlockHeaderJson `json:"signed_header_1"`
	Header_2 *SignedBeaconBlockHeaderJson `json:"signed_header_2"`
}

type IndexedAttestationJson struct {
	AttestingIndices []string             `json:"attesting_indices"`
	Data             *AttestationDataJson `json:"data"`
	Signature        string               `json:"signature" hex:"true"`
}

type AttesterSlashingJson struct {
	Attestation_1 *IndexedAttestationJson `json:"attestation_1"`
	Attestation_2 *IndexedAttestationJson `json:"attestation_2"`
}

type CheckpointJson struct {
	Epoch string `json:"epoch"`
	Root  string `json:"root" hex:"true"`
}

type AttestationDataJson struct {
	Slot            string          `json:"slot"`
	CommitteeIndex  string          `json:"index"`
	BeaconBlockRoot string          `json:"beacon_block_root" hex:"true"`
	Source          *CheckpointJson `json:"source"`
	Target          *CheckpointJson `json:"target"`
}

type BeaconBlockBodyAltairJson struct {
	RandaoReveal      string                     `json:"randao_reveal" hex:"true"`
	Eth1Data          *Eth1DataJson              `json:"eth1_data"`
	Graffiti          string                     `json:"graffiti" hex:"true"`
	ProposerSlashings []*ProposerSlashingJson    `json:"proposer_slashings"`
	AttesterSlashings []*AttesterSlashingJson    `json:"attester_slashings"`
	Attestations      []*AttestationJson         `json:"attestations"`
	Deposits          []*DepositJson             `json:"deposits"`
	VoluntaryExits    []*SignedVoluntaryExitJson `json:"voluntary_exits"`
	SyncAggregate     *SyncAggregateJson         `json:"sync_aggregate"`
}

type AttestationJson struct {
	AggregationBits string               `json:"aggregation_bits" hex:"true"`
	Data            *AttestationDataJson `json:"data"`
	Signature       string               `json:"signature" hex:"true"`
}

type SignedVoluntaryExitJson struct {
	Exit      *VoluntaryExitJson `json:"message"`
	Signature string             `json:"signature" hex:"true"`
}

type DepositJson struct {
	Proof []string          `json:"proof" hex:"true"`
	Data  *Deposit_DataJson `json:"data"`
}

type SignedBeaconBlockContainerV2Json struct {
	Phase0Block    *BeaconBlockJson          `json:"phase0_block"`
	AltairBlock    *BeaconBlockAltairJson    `json:"altair_block"`
	BellatrixBlock *BeaconBlockBellatrixJson `json:"bellatrix_block"`
	Signature      string                    `json:"signature" hex:"true"`
}

type SyncAggregateJson struct {
	SyncCommitteeBits      string `json:"sync_committee_bits" hex:"true"`
	SyncCommitteeSignature string `json:"sync_committee_signature" hex:"true"`
}

type VoluntaryExitJson struct {
	Epoch          string `json:"epoch"`
	ValidatorIndex string `json:"validator_index"`
}

type Deposit_DataJson struct {
	PublicKey             string `json:"pubkey" hex:"true"`
	WithdrawalCredentials string `json:"withdrawal_credentials" hex:"true"`
	Amount                string `json:"amount"`
	Signature             string `json:"signature" hex:"true"`
}

type BeaconBlockBellatrixJson struct {
	Slot          string                        `json:"slot"`
	ProposerIndex string                        `json:"proposer_index"`
	ParentRoot    string                        `json:"parent_root" hex:"true"`
	StateRoot     string                        `json:"state_root" hex:"true"`
	Body          *BeaconBlockBodyBellatrixJson `json:"body"`
}

type BlockV2ResponseJson struct {
	Version             string                            `json:"version" enum:"true"`
	Data                *SignedBeaconBlockContainerV2Json `json:"data"`
	ExecutionOptimistic bool                              `json:"execution_optimistic"`
}

type BeaconBlockBodyBellatrixJson struct {
	RandaoReveal      string                     `json:"randao_reveal" hex:"true"`
	Eth1Data          *Eth1DataJson              `json:"eth1_data"`
	Graffiti          string                     `json:"graffiti" hex:"true"`
	ProposerSlashings []*ProposerSlashingJson    `json:"proposer_slashings"`
	AttesterSlashings []*AttesterSlashingJson    `json:"attester_slashings"`
	Attestations      []*AttestationJson         `json:"attestations"`
	Deposits          []*DepositJson             `json:"deposits"`
	VoluntaryExits    []*SignedVoluntaryExitJson `json:"voluntary_exits"`
	SyncAggregate     *SyncAggregateJson         `json:"sync_aggregate"`
	ExecutionPayload  *ExecutionPayloadJson      `json:"execution_payload"`
}

type ExecutionPayloadJson struct {
	ParentHash    string   `json:"parent_hash" hex:"true"`
	FeeRecipient  string   `json:"fee_recipient" hex:"true"`
	StateRoot     string   `json:"state_root" hex:"true"`
	ReceiptsRoot  string   `json:"receipts_root" hex:"true"`
	LogsBloom     string   `json:"logs_bloom" hex:"true"`
	PrevRandao    string   `json:"prev_randao" hex:"true"`
	BlockNumber   string   `json:"block_number"`
	GasLimit      string   `json:"gas_limit"`
	GasUsed       string   `json:"gas_used"`
	TimeStamp     string   `json:"timestamp"`
	ExtraData     string   `json:"extra_data" hex:"true"`
	BaseFeePerGas string   `json:"base_fee_per_gas" uint256:"true"`
	BlockHash     string   `json:"block_hash" hex:"true"`
	Transactions  []string `json:"transactions" hex:"true"`
}
